require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

// In-memory storage (replace with database in production)
const authCodes = new Map();
const tokens = new Map();
const clients = new Map();

// Initialize test client
clients.set(process.env.CLIENT_ID, {
    clientSecret: process.env.CLIENT_SECRET,
    redirectUris: ['https://dev242172.service-now.com/oauth_redirect.do']
});

// Generate random token
const generateToken = () => crypto.randomBytes(32).toString('hex');

// Authorization endpoint
app.get('/oauth/authorize', (req, res) => {
    const { response_type, client_id, redirect_uri, scope, state } = req.query;

    // Validate required parameters
    if (!response_type || !client_id || !redirect_uri) {
        return res.status(400).json({ error: 'invalid_request' });
    }

    // Validate client
    const client = clients.get(client_id);
    if (!client) {
        return res.status(401).json({ error: 'unauthorized_client' });
    }

    // Validate response type
    if (response_type !== 'code') {
        return res.status(400).json({ error: 'unsupported_response_type' });
    }

    // Generate authorization code
    const authCode = generateToken();
    const codeData = {
        clientId: client_id,
        redirectUri: redirect_uri,
        scope: scope,
        expiresAt: Date.now() + (10 * 60 * 1000) // 10 minutes
    };

    authCodes.set(authCode, codeData);

    // Redirect with auth code
    const redirectUrl = new URL(redirect_uri);
    redirectUrl.searchParams.set('code', authCode);
    if (state) redirectUrl.searchParams.set('state', state);
    
    res.redirect(redirectUrl.toString());
});

// Token endpoint
app.post('/oauth/token', (req, res) => {
    const { grant_type, client_id, client_secret, code, refresh_token } = req.body;

    // Validate client credentials
    const client = clients.get(client_id);
    if (!client || client.clientSecret !== client_secret) {
        return res.status(401).json({ error: 'invalid_client' });
    }

    if (grant_type === 'authorization_code') {
        // Validate authorization code
        const codeData = authCodes.get(code);
        if (!codeData || codeData.expiresAt < Date.now()) {
            return res.status(400).json({ error: 'invalid_grant' });
        }

        // Generate tokens
        const accessToken = jwt.sign(
            { client_id, scope: codeData.scope },
            process.env.ACCESS_TOKEN_SECRET,
            { expiresIn: '1h' }
        );

        const refreshToken = generateToken();
        
        // Store refresh token
        tokens.set(refreshToken, {
            clientId: client_id,
            scope: codeData.scope
        });

        // Remove used auth code
        authCodes.delete(code);

        return res.json({
            access_token: accessToken,
            token_type: 'Bearer',
            expires_in: 3600,
            refresh_token: refreshToken
        });
    } 
    else if (grant_type === 'refresh_token') {
        // Validate refresh token
        const tokenData = tokens.get(refresh_token);
        if (!tokenData || tokenData.clientId !== client_id) {
            return res.status(400).json({ error: 'invalid_grant' });
        }

        // Generate new access token
        const accessToken = jwt.sign(
            { client_id, scope: tokenData.scope },
            process.env.ACCESS_TOKEN_SECRET,
            { expiresIn: '1h' }
        );

        return res.json({
            access_token: accessToken,
            token_type: 'Bearer',
            expires_in: 3600
        });
    } 
    else {
        return res.status(400).json({ error: 'unsupported_grant_type' });
    }
});

// Middleware to verify access token
const verifyToken = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'invalid_token' });
    }

    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ error: 'invalid_token' });
    }
};

// Protected resource endpoint
app.get('/api/data', verifyToken, (req, res) => {
    res.json({ message: 'Protected data accessed successfully' });
});

app.listen(process.env.PORT, () => {
    console.log(`OAuth 2.0 server running on port ${process.env.PORT}`);
});