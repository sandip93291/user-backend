// routes/studentRoutes.js
const express = require('express');
const db = require('../db');
const { authRequired, requireRole } = require('../middleware/authMiddleware');

const router = express.Router();

// Student sees their own profile only
router.get('/users/:id', authRequired, requireRole('student'), async (req, res) => {
    const { id } = req.params;
    console.log('Fetching user with id:', id);

    const q = `
        SELECT u.id, u.name, u.email, u.mobile, r.name as role, r.id as roleId, u.approved
        FROM users u
        JOIN roles r ON r.id = u.role_id
        WHERE u.id = $1
    `;

    try {
        const result = await db.query(q, [id]);

        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        return res.json({ user: result.rows[0] });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ message: 'Server error' });
    }
});



module.exports = router;
