# Xyz

[stoQ](https://stoq-framework.readthedocs.io/en/latest/index.html) plugin that extracts rich metadata from Zip files

## Plugin Classes

- [Worker](https://stoq-framework.readthedocs.io/en/latest/dev/workers.html)


## Configuration

All options below may be set by:

- [plugin configuration file](https://stoq-framework.readthedocs.io/en/latest/dev/plugin_overview.html#configuration)
- [`stoq` command](https://stoq-framework.readthedocs.io/en/latest/gettingstarted.html#plugin-options)
- [`Stoq` class](https://stoq-framework.readthedocs.io/en/latest/dev/core.html?highlight=plugin_opts#using-providers)

### Options

- `decompress_files` [`True`/`False`]: Decompress files within zip and store metadata

- `derive_deflate_level` [`True`/`False`]: Calculate the deflate level


## Thanks

Thanks to Sandia National Labs and Charles Smutz for authoring and open sourcing the [original code](https://github.com/sandialabs/xyz).

The original MIT license can be found in [xyz.py](xyz/xyz.py)


## Note

This version has been modified from the original to work with the stoQ framework as well as python 3.6+
