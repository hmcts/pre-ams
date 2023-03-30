const { DefaultAzureCredential } = require('@azure/identity');
const { AzureMediaServices } = require('@azure/arm-mediaservices');
const { BlobServiceClient, AnonymousCredential } = require('@azure/storage-blob');
const factory = require('../common/encoding/transformFactory');
const { AbortController } = require('@azure/abort-controller');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const url = require('whatwg-url');
const util = require('util');
const fs = require('fs');
const Buffer = require('buffer').Buffer;

// Load the .env file if it exists
const dotenv = require('dotenv');
// jsonwebtoken package used for signing JWT test tokens in this sample
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const jwksuri = process.env.JWKSURI;
// moment used for manipulation of dates and times for JWT token expirations
const moment = require('moment');
moment().format();

dotenv.config();

// This is the main Media Services client object
let mediaServicesClient;

const subscriptionId = process.env.AZURE_SUBSCRIPTION_ID;
const resourceGroup = process.env.AZURE_RESOURCE_GROUP;
const accountName = process.env.AZURE_MEDIA_SERVICES_ACCOUNT_NAME;
const algo = process.env.ALGO;
const scope = process.env.SCOPE;
const credential = new DefaultAzureCredential();

let inputFile;
let inputUrl =
  'https://amssamples.streaming.mediaservices.windows.net/2e91931e-0d29-482b-a42b-9aadc93eb825/AzurePromo.mp4';

// Timer values
const timeoutSeconds = 60 * 10;
const sleepInterval = 1000 * 2;
const setTimeoutPromise = util.promisify(setTimeout);
const outputFolder = './Output';
const namePrefix = 'streamDRM';
const issuer = process.env.ISSUER;
const azureTenantId = process.env.AZURE_TENANT_ID;
const azureClientId = process.env.AZURE_CLIENT_ID;
const symmetricKey = process.env.SYMMETRICKEY;

///////////////////////////////////////////
//   Main entry point for sample script  //
///////////////////////////////////////////
module.exports = async function (context, req) {
  // Define the name to use for the encoding Transform that will be created
  const accessToken = req.headers.authorization.split(' ')[1];
  if (!accessToken) throw Error('Authentication failed.  Invalid or missing token');

  const encodingTransformName = 'ContentAwareEncodingTransform';

  const tokenValid = await verifyToken(accessToken);

  if (tokenValid) {
    let tokenSigningKey = new Uint8Array(Buffer.from(symmetricKey, 'base64'));

    mediaServicesClient = new AzureMediaServices(credential, subscriptionId);

    try {
      console.log('Creating encoding transform...');

      let adaptiveStreamingTransform = factory.createBuiltInStandardEncoderPreset({
        presetName: 'ContentAwareEncoding',
      });

      await mediaServicesClient.transforms.createOrUpdate(resourceGroup, accountName, encodingTransformName, {
        name: encodingTransformName,
        outputs: [
          {
            preset: adaptiveStreamingTransform,
          },
        ],
      });
      console.log('Transform Created (or updated if it existed already).');

      let uniqueness = uuidv4();
      let input = await getJobInputType(uniqueness);
      let outputAssetName = `${namePrefix}-output-${uniqueness}`;
      let jobName = `${namePrefix}-job-${uniqueness}`;
      let locatorName = `locator${uniqueness}`;

      console.log('Creating the output Asset to encode content into...');
      let outputAsset = await mediaServicesClient.assets.createOrUpdate(
        resourceGroup,
        accountName,
        outputAssetName,
        {}
      );

      if (outputAsset.name !== undefined) {
        console.log("Submitting the encoding job to the Transform's job queue...");
        let job = await submitJob(encodingTransformName, jobName, input, outputAsset.name);

        console.log(`Waiting for Job - ${job.name} - to finish encoding`);
        job = await waitForJobToFinish(encodingTransformName, jobName);

        if (job.state == 'Finished') {
          await downloadResults(outputAsset.name, outputFolder);
        }
      }
    } catch (err) {
      console.log(err);
    }
  }
};

async function downloadResults(assetName, resultsFolder) {
  let date = new Date();
  let permissions = 'Read';

  date.setHours(date.getHours() + 1);
  let input = {
    permissions,
    expiryTime: date,
  };
  let listContainerSas = await mediaServicesClient.assets.listContainerSas(
    resourceGroup,
    accountName,
    assetName,
    input
  );

  if (listContainerSas.assetContainerSasUrls) {
    let containerSasUrl = listContainerSas.assetContainerSasUrls[0];
    let sasUri = url.parseURL(containerSasUrl);

    // Get the Blob service client using the Asset's SAS URL and the Anonymous credential method on the Blob service client
    const anonymousCredential = new AnonymousCredential();
    let blobClient = new BlobServiceClient(containerSasUrl, anonymousCredential);
    // We need to get the containerName here require( the SAS URL path to use later when creating the container client
    let containerName = sasUri?.path[0];
    let directory = path.join(resultsFolder, assetName);
    console.log(`Downloading output into ${directory}`);

    // Get the blob container client using the container name on the SAS URL path
    // to access the blockBlobClient needed to use the uploadFile method
    let containerClient = blobClient.getContainerClient('');

    try {
      fs.mkdirSync(directory, { recursive: true });
    } catch (err) {
      // directory exists
      console.log(err);
    }
    console.log(`Listing blobs in container ${containerName}...`);
    console.log('Downloading blobs to local directory in background...');
    let i = 1;
    for await (const blob of containerClient.listBlobsFlat({
      includeMetadata: true,
    })) {
      console.log(`Blob ${i++}: ${blob.name}`);

      let blockBlobClient = containerClient.getBlockBlobClient(blob.name);
      await blockBlobClient
        .downloadToFile(path.join(directory, blob.name), 0, undefined, {
          abortSignal: AbortController.timeout(30 * 60 * 1000),
          maxRetryRequests: 2,
          onProgress: ev => console.log(ev),
        })
        .then(() => {
          console.log(`Download file complete`);
        });
    }
  }
}

async function waitForJobToFinish(transformName, jobName) {
  let timeout = new Date();
  timeout.setSeconds(timeout.getSeconds() + timeoutSeconds);

  async function pollForJobStatus() {
    let job = await mediaServicesClient.jobs.get(resourceGroup, accountName, transformName, jobName);

    if (job.outputs != undefined) {
      console.log(`Job State is : ${job.state},  Progress: ${job.outputs[0].progress}%`);
    }

    if (job.state == 'Finished' || job.state == 'Error' || job.state == 'Canceled') {
      return job;
    } else if (new Date() > timeout) {
      console.log(`Job ${job.name} timed out. Please retry or check the source file. Stop the debugger manually here.`);
      return job;
    } else {
      await setTimeoutPromise(sleepInterval, null);
      return pollForJobStatus();
    }
  }

  return await pollForJobStatus();
}

async function getJobInputType(uniqueness) {
  if (inputFile !== undefined) {
    let assetName = namePrefix + '-input-' + uniqueness;
    await createInputAsset(assetName, inputFile);
    return factory.createJobInputAsset({
      assetName: assetName,
    });
  } else {
    return factory.createJobInputHttp({
      files: [inputUrl],
    });
  }
}

async function createInputAsset(assetName, fileToUpload) {
  let uploadSasUrl;
  let fileName;
  let sasUri;

  let asset = await mediaServicesClient.assets.createOrUpdate(resourceGroup, accountName, assetName, {});
  let date = new Date();
  let readWritePermission = 'ReadWrite';

  date.setHours(date.getHours() + 1);
  let input = {
    permissions: readWritePermission,
    expiryTime: date,
  };

  let listContainerSas = await mediaServicesClient.assets.listContainerSas(
    resourceGroup,
    accountName,
    assetName,
    input
  );
  if (listContainerSas.assetContainerSasUrls) {
    uploadSasUrl = listContainerSas.assetContainerSasUrls[0];
    fileName = path.basename(fileToUpload);
    sasUri = url.parseURL(uploadSasUrl);

    // Get the Blob service client using the Asset's SAS URL and the Anonymous credential method on the Blob service client
    const anonymousCredential = new AnonymousCredential();
    let blobClient = new BlobServiceClient(uploadSasUrl, anonymousCredential);

    let containerName = sasUri?.path[0];
    console.log(`Uploading file named ${fileName} to blob in the Asset's container...`);

    let containerClient = blobClient.getContainerClient('');
    // Next gets the blockBlobClient needed to use the uploadFile method
    let blockBlobClient = containerClient.getBlockBlobClient(fileName);

    await blockBlobClient.uploadFile(fileToUpload, {
      blockSize: 4 * 1024 * 1024, // 4MB Block size
      concurrency: 20, // 20 concurrent
      onProgress: ev => console.log(ev),
    });
  }

  return asset;
}

async function submitJob(transformName, jobName, jobInput, outputAssetName) {
  if (outputAssetName == undefined) {
    throw new Error('OutputAsset Name is not defined. Check creation of the output asset');
  }
  let jobOutputs = [
    factory.createJobOutputAsset({
      assetName: outputAssetName,
    }),
  ];

  return await mediaServicesClient.jobs.create(resourceGroup, accountName, transformName, jobName, {
    input: jobInput,
    outputs: jobOutputs,
  });
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
      console.warn(`Authorisation Error: ${err.message}`);
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
