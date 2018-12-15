# Filedir

[stoQ](https://stoq-framework.readthedocs.io/en/v2/index.html) plugin that processes a directory/file for processing, saves results, and handles archiving of payloads.

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

#### Archiver

- `archive_dir` [str]: Directory to read/save archived files from/to

- `use_sha` [`True`/`False`]: When archiving files, should archived files be saved in a directory structure based on the first five characters of the sha1 hash. For example, if the sha1 hash of the payload is `da39a3ee5e6b4b0d3255bfef95601890afd80709`, the payload will be archived to `$archive_dir/d/a/3/9/a/da39a3ee5e6b4b0d3255bfef95601890afd80709`.

#### Connector

- `results_dir` [str]: Directory where results will be saved to

- `date_mode` [`True`/`False`]: Save results to a directory structure using `date_format`

- `date_format` [str]: Append the defined datetime formatter to the output path if requested. Defaults to `%%Y/%%m/%%d`

- `compactly` [`True`/`False`]: Save results compacted (without newlines or indents)

#### Provider

- `source_dir` [str]: Directory to ingest files from

- `recursive` [`True`/`False`]: Scan `source_dir` recursviely

> Paths may be relative to the module, or a full path.
