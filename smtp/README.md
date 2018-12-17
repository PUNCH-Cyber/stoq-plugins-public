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

- `always_dispatch` [str] = Comma separated list of stoQ plugins to always send extracted attachments to

- `archive_attachments` [`True`/`False`]: Should attachments be archived?

- `extract_iocs` [`True`/`False`]: Use `iocextract` plugin to extract IOCs from objects defined in `ioc_keys`

- `ioc_keys` [str]: Comma separated list of SMTP headers to extract IOCs from. May also include `body` and/or `body_html` to include e-mail body content.

## Usage

### Monitor a Postfix Maildir for incoming e-mails

Monitor `/home/stoq/Maildir/new` for new files using the `dirmon` provider plugin, then scan the SMTP session using the `smtp` plugin. If any attachments are extracted, automatically send them to the `hash` and `yara` plugins and archive them to `/home/stoq/archive` with the `filedir` plugin. Additionally, let's also extract any IOC's found in the SMTP headers and e-mail body using the `iocextract` plugin. Finally, the results will be saved to `/home/stoq/results` using the filedir plugin:

    $ stoq run -P dirmon -A filedir -C filedir -s smtp --plugin-opts \
        dirmon:source_dir=/home/stoq/Maildir/new \
        filedir:archive_dir=/home/stoq/archive \
        filedir:results_dir=/home/stoq/results \
        smtp:always_dispatch=hash,yara \
        smtp:archive_attachments=True \
        smtp:extract_iocs=True
