# VTMIS File Feed

[stoQ](https://stoq-framework.readthedocs.io/en/latest/index.html) plugin that pulls from the [VTMIS File Feed](https://www.virustotal.com/en/documentation/private-api/#file-feed) and processes each result.

## Plugin Classes

- [Worker](https://stoq-framework.readthedocs.io/en/latest/dev/workers.html)
- [Provider](https://stoq-framework.readthedocs.io/en/latest/dev/providers.html)

## Configuration

All options below may be set by:

- [plugin configuration file](https://stoq-framework.readthedocs.io/en/latest/dev/plugin_overview.html#configuration)
- [`stoq` command](https://stoq-framework.readthedocs.io/en/latest/gettingstarted.html#plugin-options)
- [`Stoq` class](https://stoq-framework.readthedocs.io/en/latest/dev/core.html?highlight=plugin_opts#using-providers)

### Options

- `apikey` [str]: VTMIS API key

- `time_since` [str]: Time since `now` to pull from file feed. May be represented in either minutes (e.g. 1m), hours (e.g 1h) or as outlined in the [VTMIS Private API documentation](https://www.virustotal.com/en/documentation/private-api/#file-feed) (e.g. %Y%m%dT%H%M (e.g. 20190104T0900) or %Y%m%dT%H (e.g. 20190104T09)). Defaults to `1m`.

- `download` [`True`/`False]: Should each sample be downloaded and processed as an extracted file

## Usage

### Save file feed to disk

Download and process the last hours worth of the VTMIS File Feed and save to disk:

    $ stoq run -P vtmis-filefeed -A filedir --plugin-opts filedir:use_sha=False vtmis-filefeed:time_since=1h

### Kafka Queuing Example

Start `stoq` using `kafka-queue` as the provider plugin, `filedir` as the source archiver, then process the VTMIS file feed entry with `vtmis-filefeed`, then save to elasticsearch:

    $ stoq run -P kafka-queue -S filedir -a vtmis-filefeed -C elasticsearch

In another terminal, download the most recent 1 minute worth of the VTMIS file feed with the `vtmis-filefeed` provider plugin, then archive each entry with `filedir` archive plugin, and send a message to the `kafka-queue` queue for processing:

    $ stoq run -P vtmis-filefeed -A filedir -C kafka-queue
