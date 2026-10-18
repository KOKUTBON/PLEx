function findUser(req, res, collection) {
    const rawFilter = req.body.filter;
    return collection.find(_plexRejectOperators(rawFilter));
}
