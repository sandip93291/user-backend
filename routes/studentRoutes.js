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
        SELECT 
            u.id,
            u.name,
            u.email,
            u.mobile,
            r.name AS role,
            r.id AS roleId,
            u.approved,

            -- faculty mapping
            sf.faculty_id AS facultyId,
            f.name AS facultyName

        FROM users u
        JOIN roles r ON r.id = u.role_id

        -- join mapping table
        LEFT JOIN faculty_students sf ON sf.student_id = u.id

        -- join faculty user
        LEFT JOIN users f ON f.id = sf.faculty_id

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
