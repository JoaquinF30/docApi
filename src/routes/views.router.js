import express, { Router } from "express";
import ProductManager from "../dao/managers/db/productManager.js";
import CartManager from "../dao/managers/db/cartManager.js";
import privateRoutes from "../middleware/privateRoutes.js";
import publicRoutes from "../middleware/publicRoutes.js";

const router = Router();

router.use(express.json());

const productManager = new ProductManager();
const cartManager = new CartManager();

router.get("/", privateRoutes, async (req, res) => {
    const { payload } = await productManager.getAllProducts();

    res.render("home", { 
        products: payload,
    })
});

router.get("/realtimeproducts", async (req, res) => {
    const { payload } = await productManager.getAllProducts();

    res.render("realTimeProducts", { 
        products: payload,
    })
});

router.get("/chat", async (req, res) => {
    res.render("chat")
});

router.get("/products",
//  privateRoutes,
  async (req, res) => {
    const { page } = req.query;
    const { username, email } = req.session;

    try {
        const response = await productManager.getAllProducts(undefined, undefined, undefined, page);

        const renderData = {
            response: {
                ...response,
                payload: response.status === "error" ? [] : response.payload,
            },
            datosUsuario: {
                username,
                email,
            },
        };

        res.render("products", renderData);
    }
    catch(error) {
        console.log("Cannot get products with mongoose: " + error);
    }
});

router.get("/carts/:cid", async (req, res) => {
  try {
      const cart = await cartManager.getCartProductsById(req.params.cid);
      if (!cart) {
          return res.status(404).send({ status: "error", error: "El carrito no existe en la base de datos" })
      }
      return res.render("cart", cart);
  } catch (error) {
      console.log(error);
  }
});

router.get('/login', publicRoutes, (req, res) => {
  res.render('login');
});

router.get('/register', publicRoutes, (req, res) => {
  res.render('register');
});


router.get("/current", async (req, res) => {
    const { user: { username, email } } = req.session;
    const answer = {
        usuario: username,
        email
    }
    res.render('current', {answer});
})

export default router;