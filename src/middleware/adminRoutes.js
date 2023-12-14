// import logger from "../services/logger.js";

const adminRoutes = (req, res, next) => {
  if (!req.session.role || req.session.role !== "admin") {
    // logger.warning("No tienes las credenciales necesarias de administrador.");
    return res.status(401).send("Unauthorized");
  }
  next();
};

export default adminRoutes;