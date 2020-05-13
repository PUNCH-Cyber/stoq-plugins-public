# TNEFParse

[stoQ](https://stoq-framework.readthedocs.io/en/latest/index.html) plugin that extracts objects from TNEF payloads

## Plugin Classes

- [Worker](https://stoq-framework.readthedocs.io/en/latest/dev/workers.html)

## Configuration and Options

No configuration options are required.

#### Module performance

The speed of the `UnicodeDammit` decoder from `BeautifulSoup` module is much faster when the `cchardet` module is installed,
but will fall back to the `chardet` module if it is not installed.
