# Azure Blob Storage

[stoQ](https://stoq-framework.readthedocs.io/en/latest/index.html) plugin saves results and archives payloads with [Azure Blob Storage](https://azure.microsoft.com/en-us/services/storage/blobs/#features).

## Plugin Classes

- [Archiver](https://stoq-framework.readthedocs.io/en/latest/dev/archivers.html)
- [Connector](https://stoq-framework.readthedocs.io/en/latest/dev/connectors.html)

## Configuration

All options below may be set by:

- [plugin configuration file](https://stoq-framework.readthedocs.io/en/latest/dev/plugin_overview.html#configuration)
- [`stoq` command](https://stoq-framework.readthedocs.io/en/latest/gettingstarted.html#plugin-options)
- [`Stoq` class](https://stoq-framework.readthedocs.io/en/latest/dev/core.html?highlight=plugin_opts#using-providers)

### Options

- `conn_str` [str]: Azure Storage Connection string
Instructions to find credentials [here](https://docs.microsoft.com/en-us/azure/storage/blobs/storage-quickstart-blobs-python#copy-your-credentials-from-the-azure-portal)

#### Archiver

- `archive_container` [str]: Blob container where payload will be archived

- `use_sha` [True/False]: When archiving files, use the first five characters of the sha1 hash as the directory structure.
  > For example, if the sha1 hash of the payload is `da39a3ee5e6b4b0d3255bfef95601890afd80709`, the payload will be archived to `$archive_container/d/a/3/9/a/da39a3ee5e6b4b0d3255bfef95601890afd80709`.

- `use_datetime` [True/False]: Use the currentt date (YYYY/MM/DD) as the directory structure  

#### Connector

- `results_container` [str]:  Blob container where response will be saved
