import { cartsModel } from "../dao/models/carts.model.js";

export default class CartRepository {
    async addCart() { 
        await cartsModel.create({ 
            products: []
        })
    }

    async getCarts() {
        try {
          const searchedCart = await cartsModel.find().populate("products.product").lean();
          return searchedCart;
        } catch (error) {
          return undefined;
        }
    }
    
    async getCartProductsById(id) {
        try {
            const searchedCart = await cartsModel.findById(id).populate("products.product").lean();
            return searchedCart;
        } catch (error) {
            return undefined;
        }
    }

    async insertProdToCart(cartId, productId) {
        try {
            const response = await cartsModel.updateOne(
                { _id: cartId, "products.product": productId },
                { $inc: { "products.$.quantity": 1 }}
            )
            if (response.modifiedCount === 0) {
                await cartsModel.findOneAndUpdate(
                    { _id: cartId },
                    {$addToSet: {
                            products: {
                                product: productId,
                                quantity: 1
                            }
                        }
                    })
            }
            return response;
        } catch ({ name, message }) {
            console.log(name);
            console.log(message);
        }
    }

    async purchase(cartId) {
        try {
            // const response = await cartsModel.updateOne(
            //     { _id: cartId },
            //     { $set: { products } }
            // );
            return response;
        } catch (error) {
            return undefined;
        }
    }

    async updateCart(cartId, products) {
        try {
            const response = await cartsModel.updateOne(
                { _id: cartId },
                { $set: { products } }
            );
            return response;
        } catch (error) {
            return undefined;
        }
    }

    async updateProductInCart(cartId, productId, productQuantity) {
        try {
            const response = await cartsModel.updateOne(
                { _id: cartId, "products.product": productId },
                { $set: {"products.$.quantity": productQuantity.quantity } }
            );
            return response;
        } catch (error) {
            return undefined;
        }
    }

    async deleteProductFromCart(cartId, productId) {
        try {
            const searchedCart = await cartsModel.updateOne(
                { _id: cartId },
                { $pull: { products: { product: productId } } }
            );
            return searchedCart;
        } catch (error) {
            return undefined;
        }
    }

    async deleteAllProductFromCart(cartId) {
        try {
            const searchedCart = await cartsModel.updateOne(
                { _id: cartId },
                { $set: { products: [] } }
            );
            return searchedCart;
        } catch (error) {
            return undefined;
        }
    }
}
