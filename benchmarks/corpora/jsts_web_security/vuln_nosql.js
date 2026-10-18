function findUser(req, res, collection) {
    const filter = req.body.filter;
    return collection.find(filter);
}
