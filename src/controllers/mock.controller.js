import { MockingRepository } from "../repositories/Mock.repository.js";
import logger from "../services/logger.js";

const mockingRepository = new MockingRepository();

export const mockingProducts = async (req, res) => {
  try {
    const products = await mockingRepository.get();
    res.status(200).send(products);
  } catch (error) {
    logger.error(error);
  }
};