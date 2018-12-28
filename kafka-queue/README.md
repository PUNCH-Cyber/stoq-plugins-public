# Kafka Queue

[stoQ](https://stoq-framework.readthedocs.io/en/latest/index.html) plugin that publishes and consumes messages from a Kafka Server

## Plugin Classes

- [Connector](https://stoq-framework.readthedocs.io/en/latest/dev/connectors.html)
- [Provider](https://stoq-framework.readthedocs.io/en/latest/dev/providers.html)

## Configuration

All options below may be set by:

- [plugin configuration file](https://stoq-framework.readthedocs.io/en/latest/dev/plugin_overview.html#configuration)
- [`stoq` command](https://stoq-framework.readthedocs.io/en/latest/gettingstarted.html#plugin-options)
- [`Stoq` class](https://stoq-framework.readthedocs.io/en/latest/dev/core.html?highlight=plugin_opts#using-providers)

### Options

- `servers` [str]: Comma separated list of Kafka servers

- `group` [str]: Group to consume/publish messages from/to

- `topic` [str]: Kafka topic to bind to

- `retries` [int]: Retry attempts if publishing a message fails

- `publish_archive` [`True`/`False`]: When used as a Connector plugin, should the ArchiveResponses be saved, or StoqResponse? Useful for sending archived payload metadata to topic.

## Usage

### Kafka Queuing Example

Start `stoq` using `kafka-queue` as the provider plugin, `filedir` as the source archiver, then scan the payload with the `hash`, and send results to `stdout` connector:

    $ stoq run -P kafka-queue -S filedir -a hash -C stdout

In another terminal, load files from `/tmp/test-files` using the `filedir` provider plugin, then archive the payloads with `filedir` archive plugin, and send a message to the `kafka-queue` queue for processing:

    $ stoq run -P filedir -A filedir -C kafka-queue --plugin-opts filedir:source_dir=/tmp/test-files
