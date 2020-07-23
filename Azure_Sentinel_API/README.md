# Azure Sentinel Integration

[stoQ](https://stoq-framework.readthedocs.io/en/latest/index.html) plugin sends results to [Azure Sentinel](https://azure.microsoft.com/en-us/services/azure-sentinel/) using a [Azure Logic App](https://azure.microsoft.com/en-us/services/logic-apps/).

## Plugin Classes

- [Connector](https://stoq-framework.readthedocs.io/en/latest/dev/connectors.html)

## Prerequisites

- Obtain Azure Log Analytics Workspace ID and Key

## Configuration

All options below may be set by:

- [plugin configuration file](https://stoq-framework.readthedocs.io/en/latest/dev/plugin_overview.html#configuration)
- [`stoq` command](https://stoq-framework.readthedocs.io/en/latest/gettingstarted.html#plugin-options)
- [`Stoq` class](https://stoq-framework.readthedocs.io/en/latest/dev/core.html?highlight=plugin_opts#using-providers)

### Required

- `workspaceId` [str]: ClientID/ID for the Log Analytics Workspace string
IInstructions to find the ALA Workspace information [here](https://www.systemcenterautomation.com/2018/05/find-azure-log-analytics-keys/) 

- `workspaceKey` [str]: Key/Secret for the Log Analytics Workspace string
Instructions to find the ALA Workspace information [here](https://www.systemcenterautomation.com/2018/05/find-azure-log-analytics-keys/) 

### Optional

- `logType` [str]: This field denote the Log Analytics table that the log will send too. By defualt it will got to the "StoQ_CL" table