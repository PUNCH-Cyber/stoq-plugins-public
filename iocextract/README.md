# IOCExtract

[stoQ](https://stoq-framework.readthedocs.io/en/latest/index.html) plugin extract IOCs (hashes, email, domains, urls, ips, mac addresses) from a payload

## Plugin Classes

- [Worker](https://stoq-framework.readthedocs.io/en/latest/dev/workers.html)

## Configuration

All options below may be set by:

- [plugin configuration file](https://stoq-framework.readthedocs.io/en/latest/dev/plugin_overview.html#configuration)
- [`stoq` command](https://stoq-framework.readthedocs.io/en/latest/gettingstarted.html#plugin-options)
- [`Stoq` class](https://stoq-framework.readthedocs.io/en/latest/dev/core.html?highlight=plugin_opts#using-providers)

#### Module performance

The speed of the `UnicodeDammit` decoder from `BeautifulSoup` module is much faster when the `cchardet` module is installed,
but will fall back to the `chardet` module if it is not installed.

### Options

- `iana_tld_file` [str]: Path to IANA TLD file. If the file does not exist, `iocextract` will attempt to download the file from `iana_url`

- `iana_url` [str]: URL where the IANA TLD file is located

- `whitelist_file` [str]: File containing IOCs to whitelist, preventing them from being added to results.

> Paths may be relative to the module, or a full path.

### Whitelisted indicators

##### Format:

`indicator_type`:`pattern`

##### Valid Indicator Types:

| indicator type | example                                               | note                                                                                                             |
| -------------- | ----------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `ipv4`         | ipv4:10.0.0.0/8                                       | Can be an IP address or CIDR notation                                                                            |
| `ipv6`         | ipv6:A::                                              | Can be an IP address or CIDR notation                                                                            |
| `domain`       | domain:.google.com                                    | Matches a domain or hostname portion of a url. Pattern must begin with '.' to match against wildcard subdomains. |
| `email`        | email:goodguy@gmail.com                               | Exact matches only                                                                                               |
| `url`          | url:.google.com                                       | Matches the hostname portion of a url only. Pattern must begin with '.' to match against wildcard subdomains.    |
| `md5`          | md5:4648968f6cd94b6dd242ffd1f0019152                  | Exact matches only                                                                                               |
| `sha1`         | sha1:a0979561fa753a7f8c930d70d78d8e5762dfda1e         | Exact matches only                                                                                               |
| `sha256`       | sha256:d74fef91b3f07e68113adaf2c2ecc06e598040209[...] | Exact matches only                                                                                               |
| `sha512`       | 0cb8d71065af160590d3b05b729acebac410a42a5f4ff44c[...] | Exact matches only                                                                                               |

> `sha256` and `sha512` are truncated for formatting purposes. They much be exact matches to work properly.
