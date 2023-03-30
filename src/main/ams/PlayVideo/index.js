const { DefaultAzureCredential } = require('@azure/identity');
const { AzureMediaServices } = require('@azure/arm-mediaservices');
const Buffer = require('buffer').Buffer;
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const jwksuri = process.env.JWKSURI;
const moment = require('moment');
const { v4: uuidv4 } = require('uuid');
moment().format();

dotenv.config();

const subscriptionId = process.env.AZURE_SUBSCRIPTION_ID;
const resourceGroup = process.env.AZURE_RESOURCE_GROUP;
const accountName = process.env.AZURE_MEDIA_SERVICES_ACCOUNT_NAME;
const algo = process.env.ALGO;
const scope = process.env.SCOPE;
const credential = new DefaultAzureCredential();
const audience = process.env.AUDIENCE;
const issuer = process.env.ISSUER;
const azureTenantId = process.env.AZURE_TENANT_ID;
const azureClientId = process.env.AZURE_CLIENT_ID;
const contentKeyPolicyName = process.env.CONTENTPOLICYKEYNAME;
const streamingPolicyName = process.env.STREAMINGPOLICYNAME;
const symmetricKey = process.env.SYMMETRICKEY;

let mediaServicesClient = new AzureMediaServices(credential, subscriptionId);

module.exports = async function (context, req) {
  const accessToken = req.headers.authorization.split(' ')[1];
  const filename = req.body.filename;
  if (!accessToken) throw Error('Authentication failed.  Invalid or missing token');
  if (!filename) throw Error('File not found');
  if (!accessToken) throw Error('Authentication failed.  Invalid or missing token');

  const tokenValid = await verifyToken(accessToken);

  if (tokenValid) {
    const assetExists = await checkAssetExists(filename);
    if (!assetExists) throw Error('Invalid or missing file');

    let tokenSigningKey = new Uint8Array(Buffer.from(symmetricKey, 'base64'));

    try {
      let uniqueness = uuidv4();
      let locatorName = `${filename}-locator-${uniqueness}`;

      const streamingPolicyExists = await checkStreamingPolicyExists();

      if (!streamingPolicyExists) {
        await createStreamingPolicy();
      }

      let locator = await createStreamingLocator(filename, locatorName);

      let token = await getToken(issuer, audience, tokenSigningKey);

      if (locator.name !== undefined) {
        let urls = await getStreamingUrls(locator.name, token);
        context.res = {
          headers: { 'Content-Type': 'application/json' },
          body: { streamingUrl: urls },
          status: 200,
        };
      } else throw new Error('Locator was not created or Locator.name is undefined');
    } catch (err) {
      // console.log(err);
    }
  }
};

async function createStreamingPolicy() {
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

  const client = new AzureMediaServices(credential, subscriptionId);
  await client.streamingPolicies.create(resourceGroup, accountName, streamingPolicyName, parameters);
}

async function createStreamingLocator(assetName, locatorName) {
  let streamingLocator = {
    assetName,
    streamingPolicyName,
    defaultContentKeyPolicyName: contentKeyPolicyName,
  };

  let locator = await mediaServicesClient.streamingLocators.create(
    resourceGroup,
    accountName,
    locatorName,
    streamingLocator
  );

  return locator;
}

async function getStreamingUrls(locatorName, token) {
  let streamingEndpoint = await mediaServicesClient.streamingEndpoints.get(resourceGroup, accountName, 'default');

  let paths = await mediaServicesClient.streamingLocators.listPaths(resourceGroup, accountName, locatorName);

  if (paths.streamingPaths) {
    let streamingPaths = [];
    paths.streamingPaths.forEach(path => {
      path.paths?.forEach(formatPath => {
        let manifestPath = `https://${streamingEndpoint.hostName}${formatPath}`;

        streamingPaths = [
          ...streamingPaths,
          {
            path: manifestPath,
            aes: true,
            aestoken: `Bearer%20${token}`,
            playUrl: `https://ampdemo.azureedge.net/?url=${manifestPath}&aes=true&aestoken=Bearer%20${token}`,
          },
        ];
      });
    });
    return streamingPaths;
  }
}

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

async function getToken(issuer, audience, tokenSigningKey) {
  let startDate = moment().subtract(5, 'minutes').unix();
  let endDate = moment().add(1, 'day').unix();

  let claims = {
    // "userProfile" : "Admin", // This is a custom claim example. Use anything you want, but specify it first in the policy as required.
    // "urn:microsoft:azure:mediaservices:maxuses": 2 // optional feature for token replay prevention built into AMS
    exp: endDate,
    nbf: startDate,
  };

  let jwtToken = jwt.sign(claims, Buffer.from(tokenSigningKey), {
    algorithm: 'HS256',
    issuer: issuer,
    audience,
  });

  return jwtToken;
}

async function checkAssetExists(filename) {
  let assetList = [];

  for await (const asset of mediaServicesClient.assets.list(resourceGroup, accountName)) {
    assetList.push(asset.name);
  }

  return assetList.length > 0 && assetList.some(item => item === filename);
}

async function checkStreamingPolicyExists() {
  let streamingPoliciesList = [];

  for await (const policy of mediaServicesClient.streamingPolicies.list(resourceGroup, accountName)) {
    streamingPoliciesList.push(policy.name);
  }

  return streamingPoliciesList.length > 0 && streamingPoliciesList.some(item => item === streamingPolicyName);
}
