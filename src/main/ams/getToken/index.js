// For development environment - include environment variables from .env

const tokenEndpoint = process.env.TOKENENDPOINT;
const authorizeEndpoint = process.env.AUTHORIZEENDPOINT;
const grantType = 'client_credentials';
const contentType = 'application/x-www-form-urlencoded';
const scope = process.env.SCOPE;

const axios = require('axios');
const qs = require('qs');

module.exports = async (context, req) => {
  if (!req.body.client_id || !req.headers.client_secret) throw Error('Invalid request.  Missing or invalid data');

  const postData = {
    client_id: req.body.client_id,
    scope: scope,
    client_secret: req.headers.client_secret,
    grant_type: grantType,
  };

  axios.defaults.headers.post['Content-Type'] = contentType;

  let error = false;
  let response = '';

  await axios
    .post(tokenEndpoint, qs.stringify(postData))
    .then(res => {
      response = res;
    })
    .catch(err => {
      error = true;
    });

  context.res = {
    status: error ? 403 : 200,
    body: response.data,
  };
};
