import ProductsRepository from "../../../repositories/Products.repository.js";

const productsRepository = new ProductsRepository();

class ProductManager {

    async addProduct(product) {
        const res = await productsRepository.addProduct(product);
        return res;
    }

    async getAllProducts(_limit, _sort, _query, _page) {
        const res = await productsRepository.getAllProducts(_limit, _sort, _query, _page)
        return res;
    }

    async getProductById(id) {
        const res = await productsRepository.getProductById(id)
        return res;
    }

    async deleteProduct(id) {
        const res = await productsRepository.deleteProduct(id)
        return res;
    }

    async updateProduct(id, producto) {
        const res = await productsRepository.updateProduct(id, producto)
        return res;
    }
}

export default ProductManager;