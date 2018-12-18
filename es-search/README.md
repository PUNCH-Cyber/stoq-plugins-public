# ElasticSearch

[stoQ](https://stoq-framework.readthedocs.io/en/latest/index.html) plugin that saves results to [ElasticSearch](https://www.elastic.co/products/elasticsearch)

> Note: For larger deployments, it is highly recommended that the [`filedir`](../filedir/) plugin and [Filebeat](https://www.elastic.co/products/beats/filebeat) be used instead of this plugin.

## Plugin Classes

- [Connector](https://stoq-framework.readthedocs.io/en/latest/dev/connectors.html)

## Configuration

All options below may be set by:

- [plugin configuration file](https://stoq-framework.readthedocs.io/en/latest/dev/plugin_overview.html#configuration)
- [`stoq` command](https://stoq-framework.readthedocs.io/en/latest/gettingstarted.html#plugin-options)
- [`Stoq` class](https://stoq-framework.readthedocs.io/en/latest/dev/core.html?highlight=plugin_opts#using-providers)

### Options

- `es_host` [str]: Comma separated list of ElasticSearch nodes

- `es_options` [json]: ElasticSearch options as outlined in the the [documentation](http://elasticsearch-py.readthedocs.org/en/latest/api.html)

> Example: `es_options = {"port": 443, "use_ssl": true, "verify_certs": true}`

- `es_index` [str]: Index name to use for saving results

- `es_timeout` [int]: Time to wait for ES operations to complete before timing out

- `es_retry` [True/False]: Should the plugin try again if the operation failes?

- `es_max_retries` [int]: Number of retries to attempt before a timeout occurrs

- `index_by_month` [True/False]: Append `YYYY-MM` to index name
