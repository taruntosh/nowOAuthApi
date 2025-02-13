require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    
    if (!token) {
      return res.status(403).json({ message: 'No token provided' });
    }
  
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = decoded;
      next();
    } catch (err) {
      return res.status(401).json({ message: 'Invalid token' });
    }
  };
  
  // OAuth endpoint
  app.post('/oauth/token', (req, res) => {
    const { client_id, client_secret } = req.body;
  
    if (client_id !== process.env.CLIENT_ID || client_secret !== process.env.CLIENT_SECRET) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
  
    const token = jwt.sign({ client_id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ access_token: token, token_type: 'Bearer', expires_in: 3600 });
  });
  
  // Protected API endpoint example
  app.get('/api/data', verifyToken, (req, res) => {
    res.json({ message: 'Protected data accessed successfully' });
  });
  
  app.listen(process.env.PORT, () => {
    console.log(`Server running on port ${process.env.PORT}`);
  });