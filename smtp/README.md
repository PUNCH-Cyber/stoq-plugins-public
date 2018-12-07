# SMTP

[stoQ](https://stoq-framework.readthedocs.io/en/v2/index.html) plugin parses SMTP sessions and extracts attachments.

## Plugin Classes

- [Worker](https://stoq-framework.readthedocs.io/en/v2/dev/workers.html)

## Configuration

All options below may be set by:

- [plugin configuration file](https://stoq-framework.readthedocs.io/en/v2/dev/plugin_overview.html#configuration)
- [`stoq` command](https://stoq-framework.readthedocs.io/en/v2/gettingstarted.html#plugin-options)
- [`Stoq` class](https://stoq-framework.readthedocs.io/en/v2/dev/core.html?highlight=plugin_opts#using-providers)

### Options

- `omit_body` [`True`/`False`]: Save body of e-mail (text or html) to the results. If set to `False`, IOCs cannnot be extracted from the body of the e-mail.

- `extract_iocs` [`True`/`False`]: Use `iocextract` plugin to extract IOCs from objects defined in `ioc_keys`

- `ioc_keys` [str]: Comma separated list of SMTP headers to extract IOCs from. May also include `body` and/or `body_html` to include e-mail body content.
