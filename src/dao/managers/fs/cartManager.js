import fs from "fs";
import { fieldMissing, setIdIfExists } from "../../../utils.js";

class CartManager {
    path;

    static id = 1;

    constructor (path) {
        this.path = path;
    }

    async addCart() {
        const newCart = { 
            id: setIdIfExists(await this.getCarts(), CartManager.id),
            products: []
        };

        try {
            if (!fs.existsSync(this.path)) {
                const cart = [];
                cart.push(newCart);
                await fs.promises.writeFile(this.path, JSON.stringify(cart, null, "\t"));
            } 
            else {
                const cartsArchivo = await this.getCarts();
                cartsArchivo.push(newCart);
                await fs.promises.writeFile(this.path, JSON.stringify(cartsArchivo, null, "\t"))
            }
        } catch (error) {
            console.log(error);
        }
    }

    async getCarts() {
        try {
            if (!fs.existsSync(this.path)) {
                return [];
            } else {
                const archivo = await fs.promises.readFile(this.path, "utf-8");
                const archivoParseado = JSON.parse(archivo);
                return archivoParseado;
            }
        } catch ({ name, message }) {
           console.log(name);
           console.log(message);
        }

    }

    async getCartProductsById(id) {
        try {
            const carts = await this.getCarts();
            const searchedCart = carts.find(cart => cart.id === id);
            if (searchedCart === undefined) {
                throw Error("El codigo no esta asociado a un carrito.");
            }
            return searchedCart.products;
        } catch ({ name, message }) {
            console.log(name);
            console.log(message);
        }
    }

    async insertProdToCart(cartId, productId) {
        try {
            const carts = await this.getCarts();

            const cartExists = carts.some(cart => cart.id === cartId);
            if (!cartExists) {
                throw Error("El id no esta asociado a un carrito existente.");
            }

            const cartsUpdated = carts.map(cart => {
                if (cart.id === cartId) {
                    let productFound = cart.products.find(product => product.product === productId);

                    if (!productFound) {
                        cart.products.push({
                            product: productId,
                            quantity: 1
                        })
                    } else {
                        productFound.quantity++;
                    }
                } 
                return { ...cart };
            });

            await fs.promises.writeFile(this.path, JSON.stringify(cartsUpdated, null, "\t"))
            return cartExists;
        } catch ({ name, message }) {
            console.log(name);
            console.log(message);
        }
    }
}

export default CartManager;