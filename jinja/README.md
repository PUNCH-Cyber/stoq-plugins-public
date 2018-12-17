# Jinja

[stoQ](https://stoq-framework.readthedocs.io/en/v2/index.html) plugin decorates results using a template.

## Plugin Classes

- [Connector](https://stoq-framework.readthedocs.io/en/v2/dev/connectors.html)
- [Decorator](https://stoq-framework.readthedocs.io/en/v2/dev/decorators.html)

# Plugin Classes

- [Archiver](https://stoq-framework.readthedocs.io/en/v2/dev/archivers.html)
- [Connector](https://stoq-framework.readthedocs.io/en/v2/dev/connectors.html)
- [Provider](https://stoq-framework.readthedocs.io/en/v2/dev/providers.html)

## Configuration

All options below may be set by:

- [plugin configuration file](https://stoq-framework.readthedocs.io/en/v2/dev/plugin_overview.html#configuration)
- [`stoq` command](https://stoq-framework.readthedocs.io/en/v2/gettingstarted.html#plugin-options)
- [`Stoq` class](https://stoq-framework.readthedocs.io/en/v2/dev/core.html?highlight=plugin_opts#using-providers)

### Options

- `template` [str]: Jinja2 template file to use for results

## Usage

Scan a payload and display results using default template

    $ stoq scan /tmp/badfile.exe -s hash -D jinja -C jinja

    stoQ Scan Results
    -----------------

    ScanID: 0d98a884-2c47-409f-bbee-cd45fe27d493
    Date: XXXX
    Request Metadata:
    - Archive Payload: True
    Errors:

    Payloads:

    ---------------------------------------------------
    Payload ID: f2a0d66e-867a-4220-aada-83e58ceff0e9
    Size: 507904
    Extracted From: None
    Extracted By: None
    Metadata:
        - Archive Payload:
        - Dispatch To:
        - filename: b'03.exe'
    Archivers:
    Worker Results:
        hash:
        - {'sha256': '47c6e9b02324ea6c54dd95ad3fdf4b48b18775053b105e241a371a3731488c0', 'md5': '16d9f6e5491d99beb46d7ab3500c1799', 'sha1': '9e6414bf2802c98fbd13172817db80389c5eeb6a'}
