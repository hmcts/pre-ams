const { AzureMediaServices } = require('@azure/arm-mediaservices');
const { DefaultAzureCredential } = require('@azure/identity');

module.exports = async function deleteAStreamingPolicy(context) {
  const subscriptionId = process.env.AZURE_SUBSCRIPTION_ID;
  const resourceGroup = process.env.AZURE_RESOURCE_GROUP;
  const accountName = process.env.AZURE_MEDIA_SERVICES_ACCOUNT_NAME;
  const streamingPolicyName = process.env.STREAMINGPOLICYNAME;
  const credential = new DefaultAzureCredential();

  const client = new AzureMediaServices(credential, subscriptionId);

  try {
    const result = await client.streamingPolicies.delete(resourceGroup, accountName, streamingPolicyName);
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
};
