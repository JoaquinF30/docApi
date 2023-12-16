import { fieldMissing } from "../utils/utils.js";
import ProductManager from "../dao/managers/db/productManager.js";

const productsManager = new ProductManager();

export const getAll = async (req, res) => {
    const { limit, sort, query, page } = req.query;

    try {
        let response = productsManager.getAllProducts(limit, sort, query, page);
        if(response.status === "error") {
            return res.status(404).send({message: "No se encontro el recurso"});
        }
        return res.status(200).send(response);
    }
    catch(error) {
        console.log("Cannot get products with mongoose: " + error);
    }
}

export const getById = async (req, res) => {
    try {
        const searchedProduct = productsManager.getProductById(req.params.pid);
        if(!searchedProduct) {
            return res.send({message: "No se encontro el recurso"})
        }
        res.send(searchedProduct);
    }
    catch(error) {
        console.log("Cannot get product with mongoose: " + error);
        res.status(404).send({status: "error", error: "El id no existe en la base de datos"})
    }
}

export const addProduct = async (req, res) => {
    const newProduct = req.body;

    if (fieldMissing(newProduct)) {
        return res.status(500).send({ status: "error", error: "Falta informacion de alguno de los campos." })
    }
    try {
        productsManager.addProduct(newProduct);
        res.status(200).send({message: "Se ingreso el producto a la base"});
    } catch (error) {
        if (error.code === 11000) {
            return res.status(500).send({ status: "error", error: "El codigo ya existe en la base" })
        }
        console.log(error);
    }
}

export const updateProduct = async (req, res) => {
    const dbResponse = productsManager.updateProduct(req.params.pid, req.body);
    
    if (!dbResponse.acknowledged) {
        return res.status(400).send({message: "Error al actualizar el producto, revisar datos enviados."})
    }
    res.status(200).send({message: "Se actualizo el producto correctamente"});
}

export const deleteProduct = async (req, res) => {
    try {
        let deletedProduct = productsManager.deleteProduct(req.params.pid);
        if (!deletedProduct) {
            return res.status(404).send({ status: "error", error: "No se encontro el producto asociado al id" })
        }
        
        res.status(200).send({message: "Se elimino el producto correctamente"});
        if(res.statusCode === 200) {
            req.context.socketServer.emit("deletedProduct", deletedProduct);
        }
    }
    catch(error) {
        console.log("Cannot delete product with mongoose: " + error);
    }
}