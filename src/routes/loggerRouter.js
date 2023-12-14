import { Router } from "express";
import { loggerTestController } from "../controllers/logger.controller.js";

const router = Router();

router.get("/", loggerTestController);

export default router;