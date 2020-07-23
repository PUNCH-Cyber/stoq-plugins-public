# Azure Sentinel Integration

[stoQ](https://stoq-framework.readthedocs.io/en/latest/index.html) plugin sends results to [Azure Sentinel](https://azure.microsoft.com/en-us/services/azure-sentinel/) using a [Azure Logic App](https://azure.microsoft.com/en-us/services/logic-apps/).

## Plugin Classes

- [Connector](https://stoq-framework.readthedocs.io/en/latest/dev/connectors.html)

## Prerequisites

- Deploy Azure Logic App webhook listener using the "Deploy to Azure" button below
- Optionally: Adjust JSON Schema for your StoQ environment using this [link](https://docs.microsoft.com/en-us/azure/connectors/connectors-native-reqres#add-request-trigger) under section #3

## Deploy Azure Logic App

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw%2Egithubusercontent%2Ecom%2FPUNCH%2DCyber%2Fstoq%2Dplugins%2Dpublic%2Fmaster%2FAzure%5FSentinel%2Fazuredeploy%2Ejson" target="_blank">
    <img src="https://aka.ms/deploytoazurebutton""/>
</a>

## Configuration

All options below may be set by:

- [plugin configuration file](https://stoq-framework.readthedocs.io/en/latest/dev/plugin_overview.html#configuration)
- [`stoq` command](https://stoq-framework.readthedocs.io/en/latest/gettingstarted.html#plugin-options)
- [`Stoq` class](https://stoq-framework.readthedocs.io/en/latest/dev/core.html?highlight=plugin_opts#using-providers)

### Required

- `conn_str` [str]: Logic App Webhook HTTP Listener URL string
Instructions to find Post URL [here](https://docs.microsoft.com/en-us/azure/connectors/connectors-native-reqres#add-request-trigger) 