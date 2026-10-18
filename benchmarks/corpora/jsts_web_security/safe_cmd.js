const child_process = require("child_process");

function inspectLog(req, res) {
    const file = req.query.file;
    child_process.execFile("cat", ["--", file]);
}
