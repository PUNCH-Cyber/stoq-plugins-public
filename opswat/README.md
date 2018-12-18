# OPSWAT Metascan

[stoQ](https://stoq-framework.readthedocs.io/en/latest/index.html) plugin that scans payloads using [OPSWAT Metadefender](https://www.opswat.com/products/metadefender)

## Plugin Classes

- [Worker](https://stoq-framework.readthedocs.io/en/latest/dev/workers.html)

## Configuration

All options below may be set by:

- [plugin configuration file](https://stoq-framework.readthedocs.io/en/latest/dev/plugin_overview.html#configuration)
- [`stoq` command](https://stoq-framework.readthedocs.io/en/latest/gettingstarted.html#plugin-options)
- [`Stoq` class](https://stoq-framework.readthedocs.io/en/latest/dev/core.html?highlight=plugin_opts#using-providers)

### Options

- `opswat_url` [str]: URL for Metadefender

- `apikey` [str]: Metadefender API key

- `delay` [int]: Time in seconds to wait between checking for completed results

- `max_attempts` [int]: Maximum amount of attempts to retrieve results
