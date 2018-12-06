# Yara

[stoQ](https://stoq-framework.readthedocs.io/en/v2/index.html) plugin that leverages yara for [scanning](https://stoq-framework.readthedocs.io/en/v2/dev/workers.html) and [dispatching](https://stoq-framework.readthedocs.io/en/v2/dev/dispatchers.html).

## Plugin Classes

- [Worker](https://stoq-framework.readthedocs.io/en/v2/dev/workers.html)
- [Dispatcher](https://stoq-framework.readthedocs.io/en/v2/dev/dispatchers.html)

## Configuration and Options

All options below may be set by:

- [plugin configuration file](https://stoq-framework.readthedocs.io/en/v2/dev/plugin_overview.html#configuration)
- [`stoq` command](https://stoq-framework.readthedocs.io/en/v2/gettingstarted.html#plugin-options)
- [`Stoq` class](https://stoq-framework.readthedocs.io/en/v2/dev/core.html?highlight=plugin_opts#using-providers)

`worker_rules`: Path to yara rules for the scanning of a `Payload`

`dispatch_rules`: Path to yara rules for dispatching a `Payload`

> Paths may be relative to the module, or a full path.
