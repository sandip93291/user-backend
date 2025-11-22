// routes/facultyRoutes.js
const express = require('express');
const db = require('../db');
const { authRequired, requireRole } = require('../middleware/authMiddleware');

const router = express.Router();

// Faculty: create student
router.post('/users', authRequired, requireRole('faculty'), async (req, res) => {
    const facultyId = req.loggedInUser.id;
    const { name, email, mobile, password, approved } = req.body;
    const bcrypt = require('bcrypt');
    const SALT_ROUNDS = 10;

    if (!password) return res.status(400).json({ message: 'Password required' });

    try {
        // Hash password
        const hash = await bcrypt.hash(password, SALT_ROUNDS);

        // Get student role_id
        const roleRow = await db.query('SELECT id FROM roles WHERE name=$1', ['student']);
        if (roleRow.rowCount === 0) return res.status(400).json({ message: 'Student role not found' });
        const roleId = roleRow.rows[0].id;

        // Insert student into users
        const qUser = `
            INSERT INTO users (name, email, mobile, password_hash, role_id, approved)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, name, email, mobile, role_id, approved
        `;
        const userResult = await db.query(qUser, [name, email, mobile, hash, roleId, approved]);
        const student = userResult.rows[0];

        // Insert into faculty_students
        const qMapping = `
            INSERT INTO faculty_students (faculty_id, student_id)
            VALUES ($1, $2)
            RETURNING id, faculty_id, student_id
        `;
        const mappingResult = await db.query(qMapping, [facultyId, student.id]);

        student['role'] = 'student';    

        return res.status(201).json({ student, mapping: mappingResult.rows[0] });

    } catch (err) {
        console.error(err);
        return res.status(500).json({ message: 'Server error' });
    }
});



// Faculty: view students they added (list)
router.get('/users', authRequired, requireRole('faculty'), async (req, res) => {
    const facultyId = req.loggedInUser.id;
    const page = parseInt(req.query.page) || 1;       // default page 1
    const limit = 100;
    const offset = (page - 1) * limit;

    try {
        // Get total count
        const countResult = await db.query(
            'SELECT COUNT(*) FROM faculty_students WHERE faculty_id = $1',
            [facultyId]
        );
        const total = parseInt(countResult.rows[0].count);

        // Get paginated data
        const q = `
            SELECT 
                u.id, 
                u.name, 
                u.email, 
                u.mobile, 
                u.approved,
                u.role_id,
                fs.id as mappingId,
                fs.created_at,
                fs.updated_at,
                'student' as role
            FROM faculty_students fs
            JOIN users u ON u.id = fs.student_id
            WHERE fs.faculty_id = $1
            ORDER BY u.created_at DESC
            LIMIT $2 OFFSET $3
        `;
        const result = await db.query(q, [facultyId, limit, offset]);

        return res.json({
            users: result.rows,
            page,
            limit,
            totalPages: Math.ceil(total / limit),
            totalItems: total
        });

    } catch (err) {
        console.error(err);
        return res.status(500).json({ message: 'Server error' });
    }
});


// Faculty: update student info and optionally mapping
router.put('/users/:id', authRequired, requireRole('faculty'), async (req, res) => {
    const facultyId = req.loggedInUser.id;
    const { id } = req.params; // student id
    const { name, email, mobile, password, approved } = req.body;
    const bcrypt = require('bcrypt');
    const SALT_ROUNDS = 10;

    try {
        // Check if student belongs to this faculty
        const mappingCheck = await db.query(
            'SELECT * FROM faculty_students WHERE faculty_id=$1 AND student_id=$2',
            [facultyId, id]
        );
        if (mappingCheck.rowCount === 0) return res.status(403).json({ message: 'Not authorized to update this student' });

        // Hash password if provided
        let passwordHash;
        if (password) passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

        // Update student
        const qUpdate = `
            UPDATE users
            SET name=$1,
                email=$2,
                mobile=$3,
                password_hash=COALESCE($4, password_hash),
                approved=COALESCE($5, approved)
            WHERE id=$6 AND role_id=(SELECT id FROM roles WHERE name='student')
            RETURNING id, name, email, mobile, approved
        `;
        const r = await db.query(qUpdate, [name, email, mobile, passwordHash, approved, id]);

        if (r.rowCount === 0) return res.status(404).json({ message: 'Student not found' });

        return res.json({ student: r.rows[0] });

    } catch (err) {
        console.error(err);
        return res.status(500).json({ message: 'Server error' });
    }
});

// Faculty: view a student by ID
router.get('/users/:id', authRequired, requireRole('faculty'), async (req, res) => {
    const facultyId = req.loggedInUser.id;
    const { id } = req.params; // student id

    try {
        // Check if the student belongs to this faculty
        const q = `
            SELECT 
                u.id, 
                u.name, 
                u.email, 
                u.mobile, 
                u.approved,
                u.role_id,
                'student' as role,
                fs.id as mappingId,
                fs.created_at,
                fs.updated_at
            FROM faculty_students fs
            JOIN users u ON u.id = fs.student_id
            WHERE fs.faculty_id = $1 AND fs.student_id = $2
        `;

        const result = await db.query(q, [facultyId, id]);

        if (result.rowCount === 0) {
            return res.status(404).json({ message: 'Student not found or not assigned to you' });
        }

        return res.json({ user: result.rows[0] });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ message: 'Server error' });
    }
});


module.exports = router;
