// routes/authRoutes.js
const express = require('express');
const bcrypt = require('bcrypt');
const db = require('../db');
const { signToken } = require('../auth');
const { v4: uuidv4 } = require('uuid');
const { authRequired, requireRole } = require('../middleware/authMiddleware');

const router = express.Router();
const SALT_ROUNDS = 10;


// LOGIN (mobile or email) -> returns JWT;
router.post('/login', async (req, res) => {
    const { identifier, password } = req.body; // identifier = email or mobile

    if (!identifier || !password) {
        return res.status(400).json({ message: 'identifier and password required' });
    }

    try {
        // Check if identifier is email
        const isEmail = identifier.includes('@');

        const query = isEmail
            ? `SELECT u.id, u.name, u.email, u.mobile, u.password_hash, r.id as roleId, r.name as role, u.approved
           FROM users u
           LEFT JOIN roles r ON r.id = u.role_id
           WHERE u.email=$1`
            : `SELECT u.id, u.name, u.email, u.mobile, u.password_hash, r.id as roleId, r.name as role, u.approved
           FROM users u
           LEFT JOIN roles r ON r.id = u.role_id
           WHERE u.mobile=$1`;

        const result = await db.query(query, [identifier]);

        if (result.rowCount === 0) {
            return res.status(401).json({ message: 'User not found' });
        }

        const user = result.rows[0];

        // Validate password
        const isMatch = await bcrypt.compare(password, user.password_hash);
        // if (!isMatch) {
        //     return res.status(401).json({ message: 'Invalid password' });
        // }

        // Check approval
        if (!user.approved) {
            return res.status(403).json({ message: 'User not approved by admin yet' });
        }

        // Auto logout previous sessions
        await db.query(`UPDATE sessions SET revoked=true WHERE user_id=$1`, [user.id]);

        // Create unique session id (JTI)
        const sessionuuid = uuidv4();

        // Create JWT token
        const { token } = signToken({
            userId: user.id,
            roleId: user.roleId,
            role: user.role,
            name: user.name,
            email: user.email,
            sessionId: sessionuuid
        });

        // Set expiry (1 hour)
        const expiresAt = new Date(Date.now() + 60 * 60 * 1000);

        // Store session in DB
        await db.query(
            `INSERT INTO sessions (id, user_id, issued_at, expires_at, revoked)
         VALUES ($1, $2, now(), $3, false)`,
            [sessionuuid, user.id, expiresAt]
        );

        return res.json({
            message: 'Login successful',
            token: token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                mobile: user.mobile,
                roleId: user.roleId,
                role: user.role
            }
        });

    } catch (err) {
        console.error('LOGIN ERROR:', err);
        return res.status(500).json({ message: 'Server error' });
    }

});


// LOGOUT: revoke current session
router.post('/logout', authRequired, async (req, res) => {
    const auth = req.headers.authorization;
    if (!auth || !auth.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'Missing token' });
    }
    const token = auth.split(' ')[1];
    try {
        const payload = jwt.verify(token, process.env.JWT_SECRET); // verify token
        const sessionId = payload.sessionId;
        await db.query('UPDATE sessions SET revoked=true WHERE id=$1', [sessionId]);
        res.clearCookie('auth_token'); // clear cookie as well
        return res.json({ message: 'Logged out' });
    } catch (err) {
        console.error(err.message);
        return res.status(401).json({ message: 'Invalid token' });
    }
});

module.exports = router;
