# SSDeep Hash

[stoQ](https://stoq-framework.readthedocs.io/en/v2/index.html) plugin that generates an ssdeep hash of a payload.

## Plugin Classes

- [Worker](https://stoq-framework.readthedocs.io/en/v2/dev/workers.html)

## Configuration and Options

No configuration options are required.

## Install Notes

1. Depending on the system, some additional requirements may need to be installed for ssdeep to work properly. Please see the [ssdeep installation](https://python-ssdeep.readthedocs.io/en/latest/installation.html) instructions for additional details. On debian based systems, minimum requirements are:
   - build-essential
   - libffi-dev
   - python3
   - python3-dev
   - python3-pip
   - libfuzzy-dev
