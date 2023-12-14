// import logger from "../services/logger.js";

const userRoutes = (req, res, next) => {
  if (!req.session.role || req.session.role !== "user") {
    // logger.warning("No tienes las credenciales necesarias de usuario.");
    return res.status(401).send("No esta autorizado");
  }
  next();
};

export default userRoutes;