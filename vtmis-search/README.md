# VTMIS Search

[stoQ](https://stoq-framework.readthedocs.io/en/latest/index.html) plugin that searches [VTMIS](https://www.virustotal.com) for sha1 hash of a payload or from results of `iocextract` plugin.

## Plugin Classes

- [Worker](https://stoq-framework.readthedocs.io/en/latest/dev/workers.html)
- [Dispatcher](https://stoq-framework.readthedocs.io/en/latest/dev/dispatchers.html)
- [DeepDispatcher](https://stoq-framework.readthedocs.io/en/latest/dev/deepdispatchers.html)

## Configuration

All options below may be set by:

- [plugin configuration file](https://stoq-framework.readthedocs.io/en/latest/dev/plugin_overview.html#configuration)
- [`stoq` command](https://stoq-framework.readthedocs.io/en/latest/gettingstarted.html#plugin-options)
- [`Stoq` class](https://stoq-framework.readthedocs.io/en/latest/dev/core.html?highlight=plugin_opts#using-providers)

### Options

- `apikey` [str]: VTMIS API key
