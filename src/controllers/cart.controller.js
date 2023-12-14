import CartManager from "../dao/managers/db/cartManager.js";

const cartManager = new CartManager();

export const getAll = async (_req, res) => {
    const carts = cartManager.getCarts();
    if (!carts) {
        return res.status(204).send({ message: "No existen carritos" })
    }
    return res.status(200).send(carts);
}

export const getById = async (req, res) => {
    try {
        const products = cartManager.getCartProductsById(req.params.cid);
        if (!products) {
            return res.status(404).send({ status: "error", error: "El carrito no existe en la base de datos" })
        }
        res.status(200).send(products);
    } catch (error) {
        console.log(error);
    }   
}

export const createCart = async (req, res) => {
    cartManager.addCart()
    res.status(200).send({ message: "El carrito se creo con exito!" });
}

export const insertProdToCart = async (req, res) => {
    const response = cartManager.insertProdToCart(req.params.cid, req.params.pid);
    if (!response) {
        return res.status(404).send({ status: "error", error: "El id no esta asociado a un carrito existente." })
    }
    
    res.status(200).send({ message: "Se ingreso el producto al carrito con exito" });
}

export const purchase = async (req, res) => {
    // COMPLETAR
    const response = cartManager.purchase(req.params.cid);

    res.status(200).send({ message: "Se ingreso el producto al carrito con exito" });
}

export const updateCart = async (req, res) => {
    try {
        let updatedCart = cartManager.updateCart(req.params.cid, req.body);

        if (updatedCart.modifiedCount === 0) {
            return res.status(404).send({ status: "error", error: "No se encontro el id asociado al carrito" })
        }

        res.status(200).send({message: "Se actualizaron los productos del carrito correctamente"});
    }
    catch(error) {
        console.log("Cannot delete product with mongoose: " + error);
    }
}

export const updateProductInCart = async (req, res) => {
    const { cid, pid } = req.params;

    try {
        let updatedCart = cartManager.updateProductInCart(cid, pid, req.body);

        if (updatedCart.modifiedCount === 0) {
            return res.status(404).send({ status: "error", error: "No se encontro el id asociado al carrito" })
        }

        res.status(200).send({message: "Se actualizo la cantidad del producto correctamente"});
    }
    catch(error) {
        console.log("Cannot delete product with mongoose: " + error);
    }
}

export const deleteProductFromCart = async (req, res) => {
    const { cid, pid } = req.params;

    try {
        let deletedProduct = cartManager.deleteProductFromCart(cid, pid);

        if (deletedProduct.modifiedCount === 0) {
            return res.status(404).send({ status: "error", error: "No se encontro el producto asociado al id" })
        }

        res.status(200).send({message: "Se elimino el producto correctamente"});
    }
    catch(error) {
        console.log("Cannot delete product with mongoose: " + error);
    }
}

export const deleteAllProductFromCart = async (req, res) => {
    try {
        let deletedProduct = cartManager.deleteAllProductFromCart(req.params.cid);

        if (deletedProduct.modifiedCount === 0) {
            return res.status(404).send({ status: "error", error: "No se encontro el producto asociado al id" })
        }

        res.status(200).send({message: "Se elimino el producto correctamente"});
    }
    catch(error) {
        console.log("Cannot delete product with mongoose: " + error);
    }
}