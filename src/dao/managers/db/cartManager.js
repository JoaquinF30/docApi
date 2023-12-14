import CartRepository  from "../../../repositories/Cart.repository.js";

const cartService = new CartRepository();
class CartManager {

    async addCart() {
        const res = await cartService.addCart();
        return res;
    }

    async getCarts() {
        const res = await cartService.getCarts();
        return res;
    }

    async getCartProductsById(id) {
        const res = await cartService.getCartProductsById(id);
        return res;
    }

    async insertProdToCart(cartId, productId) {
        const res = await cartService.insertProdToCart(cartId, productId);
        return res;
    }

    async purchase(cartId) {
        const res = await cartService.purchase(cartId);
        return res;
    }

    async updateCart(cartId, products) {
        const res = await cartService.updateCart(cartId, products);
        return res;
    }

    async updateProductInCart(cartId, productId, productQuantity) {
        const res = await cartService.updateProductInCart(cartId, productId, productQuantity);
        return res;
    }

    async deleteProductFromCart(cartId, productId) {
        const res = await cartService.deleteProductFromCart(cartId, productId);
        return res;
    }

    async deleteAllProductFromCart(cartId) {
        const res = await cartService.deleteAllProductFromCart(cartId);
        return res;
    }
}

export default CartManager;