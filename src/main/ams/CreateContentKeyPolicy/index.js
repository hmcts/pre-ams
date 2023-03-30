const { AzureMediaServices } = require('@azure/arm-mediaservices');
const { DefaultAzureCredential } = require('@azure/identity');
const Buffer = require('buffer').Buffer;

const subscriptionId = process.env.AZURE_SUBSCRIPTION_ID;
const resourceGroup = process.env.AZURE_RESOURCE_GROUP;
const accountName = process.env.AZURE_MEDIA_SERVICES_ACCOUNT_NAME;
const contentKeyPolicyName = process.env.CONTENTPOLICYKEYNAME;
const azureTenantId = process.env.AZURE_TENANT_ID;
const azureClientId = process.env.AZURE_CLIENT_ID;
const algo = process.env.ALGO;
const scope = process.env.SCOPE;
const audience = process.env.AUDIENCE;
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const issuer = process.env.ISSUER;
const jwksuri = process.env.JWKSURI;
const symmetricKey = process.env.SYMMETRICKEY;

module.exports = async function createOrUpdateContentKeyPolicy(context, req) {
  const accessToken = req.headers.authorization.split(' ')[1];
  if (!accessToken) throw Error('Authentication failed.  Invalid or missing token');

  const tokenValid = await verifyToken(accessToken);

  if (tokenValid) {
    // This is an constant secret when moving to a production system and should be kept in a Key Vault.
    let tokenSigningKey = new Uint8Array(Buffer.from(symmetricKey, 'base64'));

    const parameters = {
      description: 'PRE Content Key Policy',
      options: [
        {
          name: 'ClearKeyOption',
          configuration: {
            odataType: '#Microsoft.Media.ContentKeyPolicyClearKeyConfiguration',
          },
          restriction: {
            odataType: '#Microsoft.Media.ContentKeyPolicyTokenRestriction',
            audience,
            issuer,
            primaryVerificationKey: {
              odataType: '#Microsoft.Media.ContentKeyPolicySymmetricTokenKey',
              keyValue: tokenSigningKey,
            },
            restrictionTokenType: 'Jwt',
          },
        },
      ],
    };
    const credential = new DefaultAzureCredential();
    const client = new AzureMediaServices(credential, subscriptionId);

    try {
      const result = await client.contentKeyPolicies.createOrUpdate(
        resourceGroup,
        accountName,
        contentKeyPolicyName,
        parameters
      );
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
