# Mongodb

[stoQ](https://stoq-framework.readthedocs.io/en/latest/index.html) plugin that saves results and archives payloads to/from MongoDB.

## Plugin Classes

- [Archiver](https://stoq-framework.readthedocs.io/en/latest/dev/archivers.html)
- [Connector](https://stoq-framework.readthedocs.io/en/latest/dev/connectors.html)

## Configuration

All options below may be set by:

- [plugin configuration file](https://stoq-framework.readthedocs.io/en/latest/dev/plugin_overview.html#configuration)
- [`stoq` command](https://stoq-framework.readthedocs.io/en/latest/gettingstarted.html#plugin-options)
- [`Stoq` class](https://stoq-framework.readthedocs.io/en/latest/dev/core.html?highlight=plugin_opts#using-providers)

### Options

- `mongodb_uri` [str]: MongoDB URI

> Must be formatted as described in the [MongoDB documentation](https://docs.mongodb.com/manual/reference/connection-string/)

- `mongodb_collection` [str]: MongoDB Collection name when saving results.

> Defaults to `stoq`.
