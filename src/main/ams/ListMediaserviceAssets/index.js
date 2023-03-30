const { DefaultAzureCredential } = require('@azure/identity');
const { AzureMediaServices } = require('@azure/arm-mediaservices');
const dotenv = require('dotenv');

dotenv.config();

const subscriptionId = process.env.AZURE_SUBSCRIPTION_ID;
const resourceGroup = process.env.AZURE_RESOURCE_GROUP;
const accountName = process.env.AZURE_MEDIA_SERVICES_ACCOUNT_NAME;
const credential = new DefaultAzureCredential();
const scope = process.env.SCOPE;
const algo = process.env.ALGO;
const issuer = process.env.ISSUER;
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const jwksuri = process.env.JWKSURI;
const azureTenantId = process.env.AZURE_TENANT_ID;
const azureClientId = process.env.AZURE_CLIENT_ID;

let mediaServicesClient = new AzureMediaServices(credential, subscriptionId);

module.exports = async function listMediaAssetExists(context, req) {
  const accessToken = req.headers.authorization.split(' ')[1];
  if (!accessToken) throw Error('Authentication failed.  Invalid or missing token');

  const tokenValid = await verifyToken(accessToken);

  if (tokenValid) {
    let assetList = [];

    try {
      for await (const asset of mediaServicesClient.assets.list(resourceGroup, accountName, { top: 1000 })) {
        assetList.push(asset.name);
      }

      context.res = {
        headers: { 'Content-Type': 'application/json' },
        body: assetList,
        status: 200,
      };
    } catch (err) {
      context.res = {
        headers: { 'Content-Type': 'application/json' },
        body: err,
        status: 400,
      };
    }
  }
};

async function verifyToken(token) {
  const decoded = jwt.decode(token, { complete: true });
  const header = decoded.header;

  if (!header) throw Error('Authentication failed.  Invalid token');

  const verifyOptions = {
    algorithms: algo,
    issuer,
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
