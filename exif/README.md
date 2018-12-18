# ExifTool

[stoQ](https://stoq-framework.readthedocs.io/en/latest/index.html) plugin that scans a payload using [ExifTool](https://www.sno.phy.queensu.ca/~phil/exiftool/)

## Plugin Classes

- [Worker](https://stoq-framework.readthedocs.io/en/latest/dev/workers.html)

## Configuration

All options below may be set by:

- [plugin configuration file](https://stoq-framework.readthedocs.io/en/latest/dev/plugin_overview.html#configuration)
- [`stoq` command](https://stoq-framework.readthedocs.io/en/latest/gettingstarted.html#plugin-options)
- [`Stoq` class](https://stoq-framework.readthedocs.io/en/latest/dev/core.html?highlight=plugin_opts#using-providers)

### Options

- `bin_path` [str]: Path to xorsearch binary

> Paths may be relative to the module, or a full path.

## Install Notes

> Additional requirements may need to be installed for ExifTool to work properly. Please see the [ExifTool](https://www.sno.phy.queensu.ca/~phil/exiftool/) website for additional details. On debian based systems, minimum requirements are: `libimage-exiftool-perl` and the `exiftool` binary.
