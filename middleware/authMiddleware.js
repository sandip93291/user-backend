// middleware/authMiddleware.js
const db = require('../db');
const { verifyToken } = require('../auth');

async function authRequired(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ message: 'Missing token' });
  const token = auth.split(' ')[1];

  try {
    const payload = verifyToken(token);
    const sessionId = payload.sessionId;
    const q = 'SELECT * FROM sessions WHERE id=$1 AND user_id=$2 AND revoked=false';
    const r = await db.query(q, [sessionId, payload.userId]);
    if (r.rowCount === 0) return res.status(401).json({ message: 'Session invalid or logged out' });

    req.loggedInUser = {
      id: payload.userId,
      role: payload.role,
      roleId: payload.roleId,
      name: payload.name,
      email: payload.email
    };

    next();
  } catch (err) {
    console.error(err);
    return res.status(401).json({ message: 'Invalid token' });
  }
}

function requireRole(...allowed) {
  return (req, res, next) => {
    if (!req.loggedInUser) return res.status(401).json({ message: 'Not authenticated' });
    if (!allowed.includes(req.loggedInUser.role)) return res.status(403).json({ message: 'Forbidden' });
    next();
  };
}

module.exports = { authRequired, requireRole };
