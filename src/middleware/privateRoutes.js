const privateRoutes = (req, res, next) => {
    if(!req.user) {
        return res.redirect("/login")
    }
    next();
};

export default privateRoutes;