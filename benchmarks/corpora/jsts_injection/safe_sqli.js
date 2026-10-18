const mysql = require('mysql');

function getUser(req, res) {
    const userId = req.query.id;
    const query = 'SELECT * FROM users WHERE id = ?';
    db.query(query, [userId], (err, results) => {
        res.json(results);
    });
}
