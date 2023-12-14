import logger from "../services/logger.js";

export const loggerTestController = async (req, res) => {
  try {
    logger.debug("Debug logger error");
    logger.http("Http logger error");
    logger.info("Info logger error");
    logger.warning("Warning logger error");
    logger.error("Error level logger");
    logger.fatal("Fatal logger error");

    res.status(200).send("Logger")
  } catch (error) {
    logger.error(error);
  }
};