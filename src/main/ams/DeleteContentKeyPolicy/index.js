const { AzureMediaServices } = require('@azure/arm-mediaservices');
const { DefaultAzureCredential } = require('@azure/identity');

module.exports = async function deleteAKeyPolicy(context) {
  const subscriptionId = process.env.AZURE_SUBSCRIPTION_ID;
  const resourceGroup = process.env.AZURE_RESOURCE_GROUP;
  const accountName = process.env.AZURE_MEDIA_SERVICES_ACCOUNT_NAME;
  const contentKeyPolicyName = process.env.CONTENTPOLICYKEYNAME;

  const credential = new DefaultAzureCredential();
  const client = new AzureMediaServices(credential, subscriptionId);

  try {
    const result = await client.contentKeyPolicies.delete(resourceGroup, accountName, contentKeyPolicyName);
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
