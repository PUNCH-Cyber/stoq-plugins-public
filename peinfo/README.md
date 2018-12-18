# peinfo

[stoQ](https://stoq-framework.readthedocs.io/en/latest/index.html) plugin that parses PE executable files and produces metadata about the payload.

## Plugin Classes

- [Worker](https://stoq-framework.readthedocs.io/en/latest/dev/workers.html)

## Configuration

All options below may be set by:

- [plugin configuration file](https://stoq-framework.readthedocs.io/en/latest/dev/plugin_overview.html#configuration)
- [`stoq` command](https://stoq-framework.readthedocs.io/en/latest/gettingstarted.html#plugin-options)
- [`Stoq` class](https://stoq-framework.readthedocs.io/en/latest/dev/core.html?highlight=plugin_opts#using-providers)

### Options

- `peidrules` [str]: Path to peid rules file

> Paths may be relative to the module, or a full path.
