import express, { Router } from "express";
import { getAll, addProduct, getById, updateProduct, deleteProduct } from "../controllers/products.controller.js"
import adminRoutes from "../middleware/adminRoutes.js";

const router = Router();

router.use(express.json());

router.get("/", getAll);
router.get("/:pid", getById);
router.post("/", adminRoutes, addProduct);
router.put("/:pid", adminRoutes, updateProduct);
router.delete("/:pid", adminRoutes, deleteProduct);

export default router;