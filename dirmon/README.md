# Dirmon

[stoQ](https://stoq-framework.readthedocs.io/en/latest/index.html) plugin monitors a directory for newly created files then provides the content of the file to `stoQ` for processing.

## Plugin Classes

- [Provider](https://stoq-framework.readthedocs.io/en/latest/dev/providers.html)

## Configuration

All options below may be set by:

- [plugin configuration file](https://stoq-framework.readthedocs.io/en/latest/dev/plugin_overview.html#configuration)
- [`stoq` command](https://stoq-framework.readthedocs.io/en/latest/gettingstarted.html#plugin-options)
- [`Stoq` class](https://stoq-framework.readthedocs.io/en/latest/dev/core.html?highlight=plugin_opts#using-providers)

### Options

- `source_dir` [str]: Directory to monitor for new files

> Paths may be relative to the module, or a full path.
