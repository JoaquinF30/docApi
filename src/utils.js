import { fileURLToPath } from "url";
import { dirname } from "path";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const __filename = fileURLToPath(import.meta.url);

const PRIVATE_KEY = "llavePrivada"

export const __dirname = dirname(__filename);

export const fieldMissing = (product) => {
    const { title, description, price, thumbnails, code, stock, category, status } = product;

    return !title || !description || price === undefined || !code || stock === undefined || !category || status === undefined || !Array.isArray(thumbnails);
}

export const setIdIfExists = (products, id) => {
    if (products.length === 0) {
        return id;
    }
    const idExists = products.some(product => product.id === id);
    const newId = products[products.length - 1].id + 1;
    if (idExists) {
        return newId;
    } else {
        return id;
    }
}

export const adaptQuery = (query) => {
    const isPropertyNumber = query.split(':')[0] === "price" || "stock";
    const matchValue = isPropertyNumber ? parseInt(query.split(':')[1]) : query.split(':')[1];
    const adaptedQuery = { [query.split(':')[0]]: matchValue };

    return adaptedQuery;
};

export const createHash = password => bcrypt.hashSync(password, bcrypt.genSaltSync(10));

export const isValidPassword = (user, password) => bcrypt.compareSync(password, user.password);

export const generateToken = (user) => {
    const token = jwt.sign({ user }, PRIVATE_KEY, { expiresIn: 30 })
    return token;
};

export const authToken = (req, res, next) => {
    const authHeader = req.headers.authorization;

    if(!authHeader) {
        return res.status(401).send({error: "Not authenticated"})
    }

    const token = authHeader.split(" ")[1];
    jwt.verify(token, PRIVATE_KEY, (error, credentials) => {
        if (error) {
            return res.status(403).send({error: "Not authorized"})
        }

        req.user = credentials.user;
        next();
    })
};

export const cookieExtractor = (req) => {
    let token = null;
    
    if (req && req.cookies) {
      token = req.cookies['token'];
    }
  
    return token;
};