import winston from "winston";
import dotenv from "dotenv";

dotenv.config();

const customLevelsOptions = {
  levels: { fatal: 0, error: 1, warning: 2, info: 3, http: 4, debug: 5 },
  colors: {
    fatal: "black",
    error: "red",
    warning: "yellow",
    info: "blue",
    http: "green",
    debug: "white",
  },
};

const config = {
    DEVELOPMENT: {
        levels: customLevelsOptions.levels,
        transports: [
        new winston.transports.Console({
            level: "debug",
            format: winston.format.combine(
            winston.format.colorize({ colors: customLevelsOptions.colors }),
            winston.format.simple()
            ),
        }),
        ],
    },
    PRODUCTION: {
        levels: customLevelsOptions.levels,
        transports: [
        new winston.transports.Console({
            level: "info",
            format: winston.format.combine(
            winston.format.colorize({ colors: customLevelsOptions.colors }),
            winston.format.simple()
            ),
        }),
        new winston.transports.File({
            filename: "src/errors.log",
            level: "error",
            format: winston.format.combine(
            winston.format.timestamp(),
            winston.format.prettyPrint()
            ), 
        }),
        ],
    },
}

const logger = winston.createLogger(config[process.env.environment])

export default logger;