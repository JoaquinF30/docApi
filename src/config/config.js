import dotenv from "dotenv";

dotenv.config();

export default {
    port: process.env.PORT,
    mongoUrl: process.env.MONGO_URL,
    github: {
        clientId: process.env.GITHUB_CLIENT_ID,
        secret: process.env.GITHUB_SECRET,
    },
}