# S3

[stoQ](https://stoq-framework.readthedocs.io/en/v2/index.html) plugin that reads and writes data to Amazon S3 buckets.

## Plugin Classes

- [Archiver](https://stoq-framework.readthedocs.io/en/v2/dev/archivers.html)
- [Connector](https://stoq-framework.readthedocs.io/en/v2/dev/connectors.html)

## Configuration

All options below may be set by:

- [plugin configuration file](https://stoq-framework.readthedocs.io/en/v2/dev/plugin_overview.html#configuration)
- [`stoq` command](https://stoq-framework.readthedocs.io/en/v2/gettingstarted.html#plugin-options)
- [`Stoq` class](https://stoq-framework.readthedocs.io/en/v2/dev/core.html?highlight=plugin_opts#using-providers)

### Options

- `access_key` [str]: AWS Access Key
- `secret_key` [str]: AWS Secret Key

#### Archiver

- `archive_bucket` [str]: S3 Bucket to read/save archived files from

- `use_sha` [`True`/`False`]: When archiving files, should archived files be saved in a directory structure based on the first five characters of the sha1 hash. For example, if the sha1 hash of the payload is `da39a3ee5e6b4b0d3255bfef95601890afd80709`, the payload will be archived to `gs://$archive_bucket/d/a/3/9/a/da39a3ee5e6b4b0d3255bfef95601890afd80709`.

#### Connector

- `connector_bucket` [str]: S3 Bucket where results will be saved to
