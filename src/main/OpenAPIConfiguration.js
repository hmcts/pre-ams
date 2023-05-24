const swaggerJsDoc = require('swagger-jsdoc');

const options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'pre-ams',
      description: 'pre ams',
      version: 'v0.0.1',
      license: {
        name: 'MIT',
        url: 'https://opensource.org/licenses/MIT',
      },
    },
    externalDocs: {
      description: 'README',
      url: 'https://github.com/hmcts/pre-ams',
    },
  },
  apis: [],
};

const openapiSpecification = swaggerJsDoc(options);

module.exports = openapiSpecification;
