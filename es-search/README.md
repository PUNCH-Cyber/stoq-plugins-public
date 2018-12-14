# ElasticSearch

[stoQ](https://stoq-framework.readthedocs.io/en/v2/index.html) plugin that saves results to [ElasticSearch](https://www.elastic.co/products/elasticsearch)

## Plugin Classes

- [Connector](https://stoq-framework.readthedocs.io/en/v2/dev/connectors.html)

## Configuration

All options below may be set by:

- [plugin configuration file](https://stoq-framework.readthedocs.io/en/v2/dev/plugin_overview.html#configuration)
- [`stoq` command](https://stoq-framework.readthedocs.io/en/v2/gettingstarted.html#plugin-options)
- [`Stoq` class](https://stoq-framework.readthedocs.io/en/v2/dev/core.html?highlight=plugin_opts#using-providers)

### Options

- `mongodb_uri` [str]: MongoDB URI

> Must be formatted as described in the [MongoDB documentation](https://docs.mongodb.com/manual/reference/connection-string/)

- `mongodb_collection` [str]: MongoDB Collection name when saving results.

> Defaults to `stoq`.

- `es_host` [str]: Comma separated list of ElasticSearch nodes

- `es_options` [json]: ElasticSearch options as outlined in the the [documentation](http://elasticsearch-py.readthedocs.org/en/latest/api.html)

> Example: `es_options = {"port": 443, "use_ssl": true, "verify_certs": true}`

- `es_index` [str]: Index name to use for saving results

- `es_timeout` [int]: Time to wait for ES operations to complete before timing out

- `es_retry` [True/False]: Should the plugin try again if the operation failes?

- `es_max_retries` [int]: Number of retries to attempt before a timeout occurrs

- `index_by_month` [True/False]: Append `YYYY-MM` to index name
