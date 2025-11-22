// auth.js
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1h';

function signToken(payload, options = {}) {
  const token = jwt.sign({ ...payload }, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN,
    ...options
  });
  return { token };
}

function verifyToken(token) {
  return jwt.verify(token, JWT_SECRET);
}

module.exports = { signToken, verifyToken };
