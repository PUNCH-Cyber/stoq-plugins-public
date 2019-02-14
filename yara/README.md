# Yara

[stoQ](https://stoq-framework.readthedocs.io/en/latest/index.html) plugin that leverages yara for [scanning](https://stoq-framework.readthedocs.io/en/latest/dev/workers.html) and [dispatching](https://stoq-framework.readthedocs.io/en/latest/dev/dispatchers.html).

## Plugin Classes

- [Worker](https://stoq-framework.readthedocs.io/en/latest/dev/workers.html)
- [Dispatcher](https://stoq-framework.readthedocs.io/en/latest/dev/dispatchers.html)

## Configuration

All options below may be set by:

- [plugin configuration file](https://stoq-framework.readthedocs.io/en/latest/dev/plugin_overview.html#configuration)
- [`stoq` command](https://stoq-framework.readthedocs.io/en/latest/gettingstarted.html#plugin-options)
- [`Stoq` class](https://stoq-framework.readthedocs.io/en/latest/dev/core.html?highlight=plugin_opts#using-providers)

### Options

- `worker_rules` [str]: Path to yara rules for the scanning of a `Payload`

- `dispatch_rules` [str]: Path to yara rules for dispatching a `Payload`

- `strings_limit` [int]: Limit the strings results in yara matches

> Paths may be relative to the module, or a full path.
