const { StorageSharedKeyCredential, BlobServiceClient } = require('@azure/storage-blob');

const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const scope = process.env.SCOPE;
const accountName = process.env.AZURE_STORAGE_ACCOUNT_NAME;
const accountKey = process.env.ACCOUNTKEY;
const algo = process.env.ALGO;
const jwksuri = process.env.JWKSURI;
const issuer = process.env.ISSUER;
const azureTenantId = process.env.AZURE_TENANT_ID;
const azureClientId = process.env.AZURE_CLIENT_ID;

// Azure Storage resource name
if (!accountName) throw Error('Azure Storage accountName not found');

// Azure Storage resource key
if (!accountKey) throw Error('Azure Storage accountKey not found');

// Create credential
const sharedKeyCredential = new StorageSharedKeyCredential(accountName, accountKey);

const baseUrl = `https://${accountName}.blob.core.windows.net`;

// Create BlobServiceClient
const blobServiceClient = new BlobServiceClient(`${baseUrl}`, sharedKeyCredential);

module.exports = async (context, req) => {
  const token = req.headers.authorization.split(' ')[1];

  if (!token) throw Error('Authentication failed.  Invalid or missing token');

  const isTokenVeried = verifyToken(token);

  const options = {
    includeDeleted: false,
    includeMetadata: false,
    includeSystem: false,
    // prefix: containerNamePrefix,
  };

  if (isTokenVeried) {
    try {
      let containerList = [];

      // List containers in stotage account
      for await (const containerItem of blobServiceClient.listContainers(options)) {
        containerList.push(containerItem.name);
      }

      context.res = {
        headers: { 'Content-Type': 'application/json' },
        body: { containerList },
        status: 200,
      };
    } catch (err) {
      context.res = {
        headers: { 'Content-Type': 'application/json' },
        body: err,
        status: 498,
      };
      throw err;
    }
  } else {
    throw Error('Authentication failed.  Invalid token');
  }
};

async function verifyToken(accessToken) {
  const decoded = jwt.decode(accessToken, { complete: true });
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
  let signingKey = key.getPublicKey();

  const payload = jwt.verify(accessToken, signingKey, verifyOptions, (err, verifiedToken) => {
    if (err) {
      return false;
    } else {
      return (
        // verifiedToken.aud === `api://${azureClientId}` &&
        verifiedToken.appid === azureClientId && verifiedToken.tid === azureTenantId
      );
    }
  });

  return payload;
}
