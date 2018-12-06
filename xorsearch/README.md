# XORSearch

[stoQ](https://stoq-framework.readthedocs.io/en/v2/index.html) plugin that scans a payload using [XORSearch](https://blog.didierstevens.com/programs/xorsearch/)

> Note: XORSearch binary needs to be installed for this plugin to operate properly.

## Plugin Classes

- [Worker](https://stoq-framework.readthedocs.io/en/v2/dev/workers.html)

## Configuration

All options below may be set by:

- [plugin configuration file](https://stoq-framework.readthedocs.io/en/v2/dev/plugin_overview.html#configuration)
- [`stoq` command](https://stoq-framework.readthedocs.io/en/v2/gettingstarted.html#plugin-options)
- [`Stoq` class](https://stoq-framework.readthedocs.io/en/v2/dev/core.html?highlight=plugin_opts#using-providers)

### Options

- `bin_path`: Path to xorsearch binary

- `terms`: Path to text file containing terms to search

> Paths may be relative to the module, or a full path.
