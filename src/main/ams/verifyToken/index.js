// For development environment - include environment variables from .env

const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const scope = process.env.SCOPE;
const algo = process.env.ALGO;
const jwksuri = process.env.JWKSURI;
const issuer = process.env.ISSUER;
const azureTenantId = process.env.AZURE_TENANT_ID;
const azureClientId = process.env.AZURE_CLIENT_ID;

module.exports = async (context, req) => {
  const token = req.headers.authorization.split(' ')[1];

  if (!token) throw Error('Authentication failed.  Invalid or missing token');

  const decoded = jwt.decode(token, { complete: true });
  const header = decoded.header;
  if (!header) throw Error('Authentication failed.  Invalid token');

  const verifyOptions = {
    algorithms: algo,
    issuer: issuer,
    aud: scope,
    subject: '',
  };

  const client = jwksClient({
    jwksUri: jwksuri,
  });

  const key = await client.getSigningKey(header.kid);
  const signingKey = key.getPublicKey();

  let error = false;
  let tokenValid = false;
  let response = '';

  jwt.verify(token, signingKey, verifyOptions, (err, verifiedToken) => {
    if (err) {
      error = true;
      response = `Authorisation Error: ${err.message}`;
      tokenValid = false;
    } else {
      tokenValid =
        verifiedToken.aud === `api://${azureClientId}` &&
        verifiedToken.appid === azureClientId &&
        verifiedToken.tid === azureTenantId;
      response = tokenValid ? 'valid' : 'Authorisation Error';
    }
  });

  context.res = {
    status: error ? 403 : 200,
    body: { tokenValid, response },
  };
};
