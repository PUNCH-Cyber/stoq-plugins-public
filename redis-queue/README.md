# Redis Queue

[stoQ](https://stoq-framework.readthedocs.io/en/v2/index.html) plugin that leverages Redis for queuing and saving results

## Plugin Classes

- [Archiver](https://stoq-framework.readthedocs.io/en/v2/dev/archivers.html)
- [Connector](https://stoq-framework.readthedocs.io/en/v2/dev/connectors.html)
- [Provider](https://stoq-framework.readthedocs.io/en/v2/dev/providers.html)
- [Worker](https://stoq-framework.readthedocs.io/en/v2/dev/workers.html)

## Configuration

All options below may be set by:

- [plugin configuration file](https://stoq-framework.readthedocs.io/en/v2/dev/plugin_overview.html#configuration)
- [`stoq` command](https://stoq-framework.readthedocs.io/en/v2/gettingstarted.html#plugin-options)
- [`Stoq` class](https://stoq-framework.readthedocs.io/en/v2/dev/core.html?highlight=plugin_opts#using-providers)

### Options

- `redis_host`: Redis hostname or ip

- `redis_port`: Redis port

- `redis_queue`: Queue name for sending and receiving messages

## Usage

### Redis Queuing Example

Start `stoq` using Redis as a queue:

    $ stoq run -P redis-queue -a hash -C stdout

In another terminal, send payloads to the redis queue for processing:

    $ stoq run -P filedir -A redis-queue --plugin-opts filedir:source_dir=/tmp/test-files

All files in `/tmp/test-files` should be sent to the redis queue, sent to the `hash` worker for scanning, and then the results sent to the `stdout` connector plugin.
