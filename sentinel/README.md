# Azure Sentinel

[stoQ](https://stoq-framework.readthedocs.io/en/latest/index.html) plugin that sends results to [Azure Sentinel](https://azure.microsoft.com/en-us/services/azure-sentinel/).

## Plugin Classes

- [Connector](https://stoq-framework.readthedocs.io/en/latest/dev/connectors.html)

## Prerequisites

- Obtain Azure Log Analytics Workspace ID and Key. Directions for obtaining the keys can be found [here](https://docs.microsoft.com/en-us/azure/azure-monitor/platform/agent-linux#obtain-workspace-id-and-key)

## Configuration

All options below may be set by:

- [plugin configuration file](https://stoq-framework.readthedocs.io/en/latest/dev/plugin_overview.html#configuration)
- [`stoq` command](https://stoq-framework.readthedocs.io/en/latest/gettingstarted.html#plugin-options)
- [`Stoq` class](https://stoq-framework.readthedocs.io/en/latest/dev/core.html?highlight=plugin_opts#using-providers)

### Required

- `workspaceid` [str]: ClientID/ID for the Log Analytics Workspace string

- `workspacekey` [str]: Key/Secret for the Log Analytics Workspace string. The primary or secondary shared key may be used.

- `logtype` [str]: This field denote the Log Analytics table that the log will send to. Log analytics will automatically append `_CL` to this value.
> Defaults to `stoQ`.
