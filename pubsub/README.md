# Redis Queue

[stoQ](https://stoq-framework.readthedocs.io/en/v2/index.html) plugin that interacts with Google Cloud Pub/Sub for queuing

## Plugin Classes

- [Archiver](https://stoq-framework.readthedocs.io/en/v2/dev/archivers.html)
- [Connector](https://stoq-framework.readthedocs.io/en/v2/dev/connectors.html)
- [Provider](https://stoq-framework.readthedocs.io/en/v2/dev/providers.html)

## Configuration

All options below may be set by:

- [plugin configuration file](https://stoq-framework.readthedocs.io/en/v2/dev/plugin_overview.html#configuration)
- [`stoq` command](https://stoq-framework.readthedocs.io/en/v2/gettingstarted.html#plugin-options)
- [`Stoq` class](https://stoq-framework.readthedocs.io/en/v2/dev/core.html?highlight=plugin_opts#using-providers)

### Options

- `project_id` [str]: Google Cloud project ID

- `pubsub_topic` [str]: Pub/Sub Topic to bind to

- `max_messages` [int]: Maximum number of messages to pull at once

## Usage

### Pub/Sub Queuing Example

Start `stoq` using Pub/Sub as a queue:

    $ stoq run -P pubsub -a hash -C stdout

In another terminal, send payloads to the redis queue for processing:

    $ stoq run -P filedir -A pubsub --plugin-opts filedir:source_dir=/tmp/test-files

Metadata for the files in `/tmp/test-files` should be sent to the pubsub queue, sent to the `hash` worker for scanning, and then the results sent to the `stdout` connector plugin.
