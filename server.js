const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 8080;

// Chiave segreta per firmare i token (da proteggere in produzione!)
const SECRET_KEY = 'mock_secret_key';

// Middleware
app.use(bodyParser.json());
app.use(cors());

// Funzione per generare token JWT
const generateToken = (payload, expiresIn = '1h') => {
  return jwt.sign(payload, SECRET_KEY, { expiresIn });
};

// Endpoint per il rilascio del token
app.post('/oauth/token', (req, res) => {
  const { grant_type, client_id, client_secret, code, username, password, refresh_token, scope } = req.body;

  // Simulazione per ogni tipo di grant
  switch (grant_type) {
    case 'authorization_code':
      if (code) {
        const token = generateToken({ client_id, scope: scope || 'default' });
        const refreshToken = generateToken({ client_id }, '7d'); // Refresh token valido per 7 giorni
        return res.json({
          access_token: token,
          token_type: 'Bearer',
          expires_in: 3600,
          refresh_token: refreshToken,
          scope: scope || 'default',
        });
      }
      break;

    case 'password':
      if (username && password) {
        const token = generateToken({ username, scope: scope || 'default' });
        const refreshToken = generateToken({ username }, '7d');
        return res.json({
          access_token: token,
          token_type: 'Bearer',
          expires_in: 3600,
          refresh_token: refreshToken,
          scope: scope || 'default',
        });
      }
      break;

    case 'client_credentials':
      if (client_id && client_secret) {
        const token = generateToken({ client_id, scope: scope || 'default' });
        return res.json({
          access_token: token,
          token_type: 'Bearer',
          expires_in: 3600,
          scope: scope || 'default',
        });
      }
      break;

    case 'refresh_token':
      if (refresh_token) {
        try {
          const decoded = jwt.verify(refresh_token, SECRET_KEY);
          const newToken = generateToken({ client_id: decoded.client_id, scope: scope || 'default' });
          return res.json({
            access_token: newToken,
            token_type: 'Bearer',
            expires_in: 3600,
          });
        } catch (err) {
          return res.status(401).json({ error: 'invalid_refresh_token' });
        }
      }
      break;

    default:
      return res.status(400).json({ error: 'unsupported_grant_type' });
  }

  return res.status(400).json({ error: 'invalid_request' });
});

// Endpoint per simulare l'autorizzazione
app.get('/oauth/authorize', (req, res) => {
  const { client_id, redirect_uri, response_type, scope, state } = req.query;

  if (response_type === 'code') {
    const mockCode = 'mock_authorization_code_12345';
    const redirectUrl = `${redirect_uri}?code=${mockCode}&state=${state}`;
    return res.redirect(redirectUrl);
  }

  return res.status(400).json({ error: 'invalid_request' });
});

// Health check endpoint
app.get('/health', (req, res) => res.send('OK'));

// Start server
app.listen(PORT, () => {
  console.log(`OAuth mock server running on port ${PORT}`);
});
