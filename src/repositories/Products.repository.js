import { productsModel } from "../dao/models/products.model.js";
import { fieldMissing, adaptQuery } from "../utils.js";

export default class ProductsRepository {

    async addProduct(product) {
        if (fieldMissing(product)) {
            console.log("Todos los campos deben proporcionarse");
            return;
        }
        await productsModel.create(product);
    }

    async getAllProducts(_limit, _sort, _query, _page) {
        const queryLimit = _limit === undefined ? 10 : +_limit;
        const sort = _sort === "asc" ? { price: 1 } : _sort === "desc" ? { price: -1 } : null;
        const queryPage = _page ? _page : 1;
        let query;
        let status = "success";

        if (_query) {
            query = adaptQuery(_query)
        };

        const { docs, totalPages, page, hasPrevPage, hasNextPage, prevPage, nextPage } = await productsModel.paginate(query, { page: queryPage, limit: queryLimit, sort, lean: true });

        if (docs.length === 0) {
            status = "error"
        };

        const prevLink = hasPrevPage
        ? `http://localhost:8080/products?page=${prevPage}`
        : null;

        const nextLink = hasNextPage
        ? `http://localhost:8080/products?page=${nextPage}`
        : null;

        const viewDTO = {
            status,
            payload: docs,
            totalPages,
            prevPage,
            nextPage,
            page,
            hasPrevPage,
            hasNextPage,
            prevLink,
            nextLink,
        }

        return viewDTO;
    }

    async getProductById(id) {
        const searchedProduct = await productsModel.findById(id).lean();
        console.log(searchedProduct);
        if (searchedProduct === undefined) {
            throw Error("El codigo no esta asociado a un producto.");
        }
        return searchedProduct;
    }

    async deleteProduct(id) {
        try {
            const jugueteAEliminar = await productsModel.deleteOne({_id: id});

            return jugueteAEliminar;

        } catch ({ name, message }) {
            console.log(name);
            console.log(message);
        }
    }

    async updateProduct(id, producto) {
        const mongoResponse = await productsModel.updateOne({_id: id}, {$set: producto})
        return mongoResponse;
    }
}
