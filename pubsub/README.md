# Redis Queue

[stoQ](https://stoq-framework.readthedocs.io/en/latest/index.html) plugin that interacts with Google Cloud Pub/Sub for queuing

## Plugin Classes

- [Archiver](https://stoq-framework.readthedocs.io/en/latest/dev/archivers.html)
- [Connector](https://stoq-framework.readthedocs.io/en/latest/dev/connectors.html)
- [Provider](https://stoq-framework.readthedocs.io/en/latest/dev/providers.html)

## Configuration

All options below may be set by:

- [plugin configuration file](https://stoq-framework.readthedocs.io/en/latest/dev/plugin_overview.html#configuration)
- [`stoq` command](https://stoq-framework.readthedocs.io/en/latest/gettingstarted.html#plugin-options)
- [`Stoq` class](https://stoq-framework.readthedocs.io/en/latest/dev/core.html?highlight=plugin_opts#using-providers)

### Options

- `project_id` [str]: Google Cloud project ID

- `topic` [str]: Pub/Sub Topic to bind to

- `subscription` [str]: Pub/Sub Subscription to monitor for messages

- `max_messages` [int]: Maximum number of messages to pull at once

## Usage

### Pub/Sub Queuing Example

Start `stoq` using `pubsub` as the provider plugin, `filedir` as the source archiver, then scan the payload with the `hash`, and send results to `stdout` connector:

    $ stoq run -P pubsub -S filedir -a hash -C stdout

In another terminal, load files from `/tmp/test-files` using the `filedir` provider plugin, then archive the payloads with `filedir` archive plugin, and send a message to the `pubsub` queue for processing:

    $ stoq run -P filedir -A filedir -C pubsub --plugin-opts filedir:source_dir=/tmp/test-files
