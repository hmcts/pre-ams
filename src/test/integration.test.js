const fs = require('fs');
const chai = require('chai');
const chaiHttp = require('chai-http');
const app = require('../main/test-app');
const openapiSpecification = require('../main/OpenAPIConfiguration.js');

chai.use(chaiHttp);
const { expect } = chai;

describe('OpenAPIPublisherTest', () => {
  it('generate swagger documentation', async () => {
    const res = await chai.request(app).get('/v3/api-docs');

    expect(res).to.have.status(200);
    expect(res.body).to.be.an('object');

    fs.writeFileSync('/tmp/openapi-specs.json', JSON.stringify(openapiSpecification, null, 2));
  });
});
