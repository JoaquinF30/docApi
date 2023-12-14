import { Router } from "express";
import { mockingProducts } from "../controllers/mock.controller.js";

const router = Router();

router.get("/", mockingProducts);

export default router;