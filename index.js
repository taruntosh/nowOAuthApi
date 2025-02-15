require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.urlencoded({ extended: true })); // Support form-urlencoded (ServiceNow option)
app.use(express.json()); // Support JSON requests (in case ServiceNow sends JSON)

// Storage for OAuth tokens and clients
const authCodes = new Map();
const tokens = new Map();
const clients = new Map();

clients.set(process.env.CLIENT_ID, {
    clientSecret: process.env.CLIENT_SECRET,
    redirectUris: ['https://dev242172.service-now.com/oauth_redirect.do']
});

const generateToken = () => crypto.randomBytes(32).toString('hex');

const logRequest = (req) => {
    console.log("\n========== 🛠 DEBUGGING STARTED 🛠 ==========");
    console.log(`📢 Incoming Request: ${req.method} ${req.originalUrl}`);
    console.log("🔹 Headers:", req.headers);
    console.log("🔹 Body:", req.body);
    console.log("🔹 Query Params:", req.query);
    console.log("========== ✅ DEBUGGING ENDED ✅ ==========\n");
};

// 🔹 OAuth Authorization Endpoint (Step 1)
app.get('/oauth/authorize', (req, res) => {
    logRequest(req);
    const { response_type, client_id, redirect_uri, scope, state } = req.query;

    if (!response_type || !client_id || !redirect_uri) {
        return res.status(400).json({ error: 'invalid_request', message: 'Missing required parameters' });
    }

    const client = clients.get(client_id);
    if (!client || !client.redirectUris.includes(redirect_uri)) {
        return res.status(401).json({ error: 'unauthorized_client', message: 'Invalid client credentials or redirect URI' });
    }

    if (response_type !== 'code') {
        return res.status(400).json({ error: 'unsupported_response_type', message: 'Only authorization code is supported' });
    }

    const authCode = generateToken();
    authCodes.set(authCode, {
        clientId: client_id,
        redirectUri: redirect_uri,
        scope,
        expiresAt: Date.now() + 10 * 60 * 1000
    });

    console.log(`✅ Generated Auth Code: ${authCode} for Client ID: ${client_id}`);

    const redirectUrl = new URL(redirect_uri);
    redirectUrl.searchParams.set('code', authCode);
    if (state) redirectUrl.searchParams.set('state', state);

    res.redirect(redirectUrl.toString());
});

// 🔹 OAuth Token Exchange Endpoint (Step 2)
app.post('/oauth/token', (req, res) => {
    logRequest(req);

    let { grant_type, code, refresh_token } = req.body;
    let client_id, client_secret;

    // 🔍 Debugging: Check the raw body received
    console.log("🔍 Debug: Raw Body Data →", req.body);

    // Extract client_id & client_secret from Basic Auth Header (if used)
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith("Basic ")) {
        console.log("🔑 Extracting client credentials from Basic Auth Header...");
        const base64Credentials = authHeader.split(" ")[1];
        const credentials = Buffer.from(base64Credentials, "base64").toString("utf-8");
        [client_id, client_secret] = credentials.split(":");
    } else {
        console.log("📝 Extracting client credentials from Request Body...");
        client_id = req.body.client_id;
        client_secret = req.body.client_secret;
    }

    // Validate required parameters
    if (!grant_type || !client_id || !client_secret) {
        console.log("❌ Missing required parameters in request.");
        return res.status(400).json({ error: 'invalid_request', message: 'Missing required parameters' });
    }

    const client = clients.get(client_id);
    if (!client || client.clientSecret !== client_secret) {
        console.log(`❌ Invalid client credentials for client_id: ${client_id}`);
        return res.status(401).json({ error: 'invalid_client', message: 'Client authentication failed' });
    }

    if (grant_type === 'authorization_code') {
        const codeData = authCodes.get(code);
        if (!codeData) {
            console.log(`❌ Invalid or expired authorization code: ${code}`);
            return res.status(400).json({ error: 'invalid_grant', message: 'Authorization code not found or already used' });
        }
        if (codeData.expiresAt < Date.now()) {
            authCodes.delete(code);
            console.log(`❌ Authorization code expired: ${code}`);
            return res.status(400).json({ error: 'invalid_grant', message: 'Authorization code has expired' });
        }

        const accessToken = jwt.sign(
            { client_id, scope: codeData.scope },
            process.env.ACCESS_TOKEN_SECRET,
            { expiresIn: '1h' }
        );

        const refreshToken = generateToken();
        tokens.set(refreshToken, { clientId: client_id, scope: codeData.scope });

        authCodes.delete(code);

        console.log(`✅ Issued Access Token: ${accessToken} for Client ID: ${client_id}`);

        return res.json({
            access_token: accessToken,
            token_type: 'Bearer',
            expires_in: 3600,
            refresh_token: refreshToken
        });
    } 
    else if (grant_type === 'refresh_token') {
        const tokenData = tokens.get(refresh_token);
        if (!tokenData || tokenData.clientId !== client_id) {
            console.log(`❌ Invalid refresh token: ${refresh_token}`);
            return res.status(400).json({ error: 'invalid_grant', message: 'Invalid or expired refresh token' });
        }

        const accessToken = jwt.sign(
            { client_id, scope: tokenData.scope },
            process.env.ACCESS_TOKEN_SECRET,
            { expiresIn: '1h' }
        );

        console.log(`🔄 Issued New Access Token via Refresh Token for Client ID: ${client_id}`);

        return res.json({
            access_token: accessToken,
            token_type: 'Bearer',
            expires_in: 3600
        });
    }

    return res.status(400).json({ error: 'unsupported_grant_type', message: 'Invalid grant type provided' });
});

// 🔹 Middleware: Verify Token for Protected Routes
const verifyToken = (req, res, next) => {
    logRequest(req);
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        console.log(`❌ Missing or Invalid Authorization Header`);
        return res.status(401).json({ error: 'invalid_token', message: 'Authorization token missing or incorrect' });
    }

    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
        req.user = decoded;
        console.log(`✅ Token Verified Successfully for Client ID: ${decoded.client_id}`);
        next();
    } catch (err) {
        console.log(`❌ Token verification failed: ${err.message}`);
        return res.status(401).json({ error: 'invalid_token', message: 'Invalid or expired token' });
    }
};

// 🔹 Protected API Endpoint
app.get('/api/data', verifyToken, (req, res) => {
    res.json({ message: 'Protected data accessed successfully' });
});

app.listen(process.env.PORT, () => {
    console.log(`🚀 OAuth 2.0 server running on port ${process.env.PORT}`);
});
