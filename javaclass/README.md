# Javaclass

[stoQ](https://stoq-framework.readthedocs.io/en/v2/index.html) plugin that decodes and extracts information from Java Class files.

## Plugin Classes

- [Worker](https://stoq-framework.readthedocs.io/en/v2/dev/workers.html)

## Configuration and Options

No configuration options are required.

## Install Notes

1. Due to an [issue](https://github.com/obriencj/python-javatools/issues/104) with [python-javatools](https://github.com/obriencj/python-javatools/), installing this plugin will fail unless `six` is already installed. To install `six`, run `pip install six`, then this plugin may be installed with `stoq install --github stoq:javaclass`

2. M2Crypto may fail to install. If so, please review the [M2Crypto installation instructions](https://github.com/mcepl/M2Crypto/blob/master/INSTALL.rst) to ensure proper installation.
