// routes/adminRoutes.js
const express = require('express');
const db = require('../db');
const { authRequired, requireRole } = require('../middleware/authMiddleware');

const router = express.Router();

// Approve a faculty (Admin only)
router.post('/approve/faculty/:facultyId', authRequired, requireRole('admin'), async (req, res) => {
    const { facultyId } = req.params;
    try {
        const result = await db.query('UPDATE users SET approved=true WHERE id=$1 AND role_id=(SELECT id FROM roles WHERE name=$2) RETURNING id, name, email, approved', [facultyId, 'faculty']);
        if (result.rowCount === 0) return res.status(404).json({ message: 'Faculty not found' });
        return res.json({ user: result.rows[0] });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ message: 'Server error' });
    }
});

// Admin: Create admin / faculty / student (full CRUD allowed for admin)
router.post('/users', authRequired, requireRole('admin'), async (req, res) => {
    const { name, email, mobile, password, role, approved } = req.body;
    const bcrypt = require('bcrypt');
    const SALT_ROUNDS = 10;
    if (!password || !role) return res.status(400).json({ message: 'password and role required' });

    try {
        const hash = await bcrypt.hash(password, SALT_ROUNDS);
        const roleRow = await db.query('SELECT id FROM roles WHERE name=$1', [role]);
        if (roleRow.rowCount === 0) return res.status(400).json({ message: 'Invalid role' });
        const roleId = roleRow.rows[0].id;
        const q = `INSERT INTO users (name,email,mobile,password_hash,role_id,approved) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id,name,email,role_id,approved`;
        const r = await db.query(q, [name, email, mobile, hash, roleId, approved]);
        return res.status(201).json({ user: r.rows[0] });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ message: 'Server error' });
    }
});

router.put('/users/:id', authRequired, requireRole('admin'), async (req, res) => {
    const { id } = req.params;
    const { name, email, mobile, password, role, approved } = req.body;
    const bcrypt = require('bcrypt');
    const SALT_ROUNDS = 10;

    try {
        // Check if user exists
        const existingUser = await db.query('SELECT * FROM users WHERE id=$1', [id]);
        if (existingUser.rowCount === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        let roleId;
        if (role) {
            const roleRow = await db.query('SELECT id FROM roles WHERE name=$1', [role]);
            if (roleRow.rowCount === 0) return res.status(400).json({ message: 'Invalid role' });
            roleId = roleRow.rows[0].id;
        }

        // Hash password if provided
        let passwordHash = existingUser.rows[0].password_hash;
        if (password) {
            passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
        }

        // Update query
        const q = `
            UPDATE users
            SET name=$1,
                email=$2,
                mobile=$3,
                password_hash=$4,
                role_id=COALESCE($5, role_id),
                approved=COALESCE($6, approved)
            WHERE id=$7
            RETURNING id, name, email, mobile, role_id, approved
        `;

        const r = await db.query(q, [name, email, mobile, passwordHash, roleId, approved, id]);

        return res.json({ user: r.rows[0] });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ message: 'Server error' });
    }
});

router.get('/users', authRequired, requireRole('admin'), async (req, res) => {
    const { page } = req.query;
    let q = `SELECT u.id, u.name, u.email, u.mobile, r.name as role, r.id as roleId, u.approved 
             FROM users u 
             JOIN roles r on r.id = u.role_id`;

    q += ' ORDER BY u.created_at DESC LIMIT 100 OFFSET $1';

    try {
        const offset = page ? (parseInt(page) - 1) * 100 : 0;

        const r = await db.query(q, [offset]);

        return res.json({ users: r.rows });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ message: 'Server error' });
    }
});

router.get('/users/:id', authRequired, requireRole('admin'), async (req, res) => {
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
