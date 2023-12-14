import { fakerES as faker } from "@faker-js/faker";
// import logger from "../services/logger.js";

export class MockingRepository {
  get = async () => {
    try {
      const products = [];
      const thumbnailUrls = Array.from({ length: 3 }, () =>
        faker.image.urlPicsumPhotos()
      );

      for (let i = 0; i <= 100; i++) {
        const product = {
          _id: faker.database.mongodbObjectId(),
          title: faker.commerce.productName(),
          description: faker.commerce.productDescription(),
          price: faker.commerce.price(),
          thumbnail: [...thumbnailUrls],
          code: faker.internet.password({ length: 20 }),
          stock: faker.number.int({ min: 0, max: 999 }),
          status: faker.datatype.boolean(0.5),
          category: faker.commerce.productAdjective(),
        };
        products.push(product);
      }

      return products;
    } catch (error) {
      console.log(error);
    }
  };
}