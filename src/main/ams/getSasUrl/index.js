const {
  BlobServiceClient,
  generateAccountSASQueryParameters,
  AccountSASPermissions,
  AccountSASServices,
  AccountSASResourceTypes,
  StorageSharedKeyCredential,
  SASProtocol,
} = require('@azure/storage-blob');

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

const sharedKeyCredential = new StorageSharedKeyCredential(accountName, accountKey);

module.exports = async (context, req) => {
  const token = req.headers.authorization.split(' ')[1];
  const containerName = req.body.containerName;
  const fileName = req.body.fileName;

  if (!containerName) throw Error('Azure Storage container not found');
  if (!fileName) throw Error('File not found');
  if (!token) throw Error('Authentication failed.  Invalid or missing token');

  const tokenValid = await verifyToken(token);

  if (tokenValid) {
    try {
      const sasToken = await createAccountSas();

      const sasUrlResponse = await useSasToken(sasToken, containerName, fileName);
      context.res = {
        headers: { 'Content-Type': 'application/json' },
        body: { sasUrl: sasUrlResponse },
        status: 200,
      };
    } catch (err) {
      context.res = {
        headers: { 'Content-Type': 'application/json' },
        body: err,
        status: 498,
      };
    }
  } else {
    context.res = {
      headers: { 'Content-Type': 'application/json' },
      body: 'Authentication failed.  Invalid token',
      status: 498,
    };
  }
};

async function verifyToken(token) {
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

  const payload = jwt.verify(token, signingKey, verifyOptions, (err, verifiedToken) => {
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

async function createAccountSas() {
  const sasOptions = {
    services: AccountSASServices.parse('btqf').toString(), // blobs, tables, queues, files
    resourceTypes: AccountSASResourceTypes.parse('cso').toString(), // service, container, object
    permissions: AccountSASPermissions.parse('rl'), // permissions
    protocol: SASProtocol.HttpsAndHttp,
    startsOn: new Date(),
    expiresOn: new Date(new Date().setDate(new Date().getDate() + 2560)), // 10 minutes
  };

  const sasToken = generateAccountSASQueryParameters(sasOptions, sharedKeyCredential).toString();

  return sasToken[0] === '?' ? sasToken : `?${sasToken}`;
}

async function useSasToken(sasToken, containerName, fileName) {
  const blobServiceClient = new BlobServiceClient(
    `https://${accountName}.blob.core.windows.net/${containerName}/${fileName}?${sasToken}`,
    sharedKeyCredential
  );

  return blobServiceClient.url;
}
