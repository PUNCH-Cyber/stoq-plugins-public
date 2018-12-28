# Redis Queue

[stoQ](https://stoq-framework.readthedocs.io/en/latest/index.html) plugin that leverages Redis for queuing and saving results

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

- `redis_host` [str]: Redis hostname or ip

- `redis_port` [int]: Redis port

- `redis_queue` [str]: Queue name for sending and receiving messages

- `publish_archive` [`True`/`False`]: When used as a Connector plugin, should the ArchiveResponses be saved, or StoqResponse? Useful for sending archived payload metadata to topic.

- `max_connections` [int]: Max connections permitted in redis connection pool

## Usage

### Redis Queuing Example

Start `stoq` using `redis-queue` as the provider plugin, `filedir` as the source archiver, then scan the payload with the `hash`, and send results to `stdout` connector:

    $ stoq run -P redis-queue -S filedir -a hash -C stdout

In another terminal, load files from `/tmp/test-files` using the `filedir` provider plugin, then archive the payloads with `filedir` archive plugin, and send a message to the `redis-queue` queue for processing:

    $ stoq run -P filedir -A filedir -C redis-queue --plugin-opts filedir:source_dir=/tmp/test-files
