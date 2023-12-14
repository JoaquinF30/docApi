import express, { Router } from "express";

import { updateCart,
    createCart,
    deleteAllProductFromCart,
    deleteProductFromCart,
    getAll,
    getById,
    insertProdToCart,
    updateProductInCart,
    purchase
} from "../controllers/cart.controller.js";
import userRoutes from "../middleware/userRoutes.js";

const router = Router();

router.use(express.json());

router.get("/", getAll);
router.get("/:cid", getById);
router.post("/", createCart);
router.post("/:cid/product/:pid", userRoutes, insertProdToCart);
router.put("/:cid", updateCart);
router.put("/:cid/products/:pid", updateProductInCart);
router.delete("/:cid/products/:pid", deleteProductFromCart);
router.delete("/:cid", deleteAllProductFromCart);
router.post("/:cid/purchase", purchase);

export default router;