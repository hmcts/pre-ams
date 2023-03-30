const { AzureMediaServices } = require('@azure/arm-mediaservices');
const { DefaultAzureCredential } = require('@azure/identity');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const jwksuri = process.env.JWKSURI;
const algo = process.env.ALGO;
const scope = process.env.SCOPE;
const issuer = process.env.ISSUER;
const azureTenantId = process.env.AZURE_TENANT_ID;
const azureClientId = process.env.AZURE_CLIENT_ID;

module.exports = async function createStreamingPolicy(context, req) {
  const accessToken = req.headers.authorization.split(' ')[1];
  if (!accessToken) throw Error('Authentication failed.  Invalid or missing token');

  const tokenValid = await verifyToken(accessToken);
  if (tokenValid) {
    const subscriptionId = process.env.AZURE_SUBSCRIPTION_ID;
    const resourceGroup = process.env.AZURE_RESOURCE_GROUP;
    const accountName = process.env.AZURE_MEDIA_SERVICES_ACCOUNT_NAME;
    const streamingPolicyName = process.env.STREAMINGPOLICYNAME;
    const credential = new DefaultAzureCredential();

    const client = new AzureMediaServices(credential, subscriptionId);
    const parameters = {
      envelopeEncryption: {
        enabledProtocols: {
          dash: true,
          download: false,
          hls: true,
          smoothStreaming: true,
        },
      },
    };

    try {
      const result = await client.streamingPolicies.create(resourceGroup, accountName, streamingPolicyName, parameters);
      context.res = {
        headers: { 'Content-Type': 'application/json' },
        body: result,
        status: 200,
      };
    } catch (err) {
      context.res = {
        headers: { 'Content-Type': 'application/json' },
        body: err,
        status: 400,
      };
    }
  } else {
    context.res = {
      headers: { 'Content-Type': 'application/json' },
      body: 'Authentication failed.  Invalid or missing token',
      status: 400,
    };
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
