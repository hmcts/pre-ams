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

// Create credential
const sharedKeyCredential = new StorageSharedKeyCredential(accountName, accountKey);
const baseUrl = `https://${accountName}.blob.core.windows.net`;

const blobServiceClient = new BlobServiceClient(`${baseUrl}`, sharedKeyCredential);

const isCorrectFileType = (fileName, filterFileTypes) => {
  const fileExtension = fileName.split('.').pop();
  return filterFileTypes.includes(fileExtension);
};

module.exports = async (context, req) => {
  const token = req.headers.authorization.split(' ')[1];
  const containerName = req.body.containerName;

  if (!containerName) throw Error('Azure Storage container not found');
  if (!token) throw Error('Authentication failed.  Invalid or missing token');

  const isTokenVeried = verifyToken(token);

  let fileTypes = req.body.fileTypes;
  if (!fileTypes) fileTypes = ['mp4'];

  if (isTokenVeried) {
    try {
      // Create container client
      const containerClient = blobServiceClient.getContainerClient(containerName);

      let blobsList = [];

      // List blobs in container
      for await (const blob of containerClient.listBlobsFlat()) {
        if (isCorrectFileType(blob.name, fileTypes)) blobsList.push(blob.name);
      }

      context.res = {
        headers: { 'Content-Type': 'application/json' },
        body: { blobsList: blobsList },
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
