const mysql = require('mysql');

function getUser(req, res) {
    const userId = req.query.id;
    const query = `SELECT * FROM users WHERE id = '${userId}'`;
    db.query(query, (err, results) => {
        res.json(results);
    });
}
