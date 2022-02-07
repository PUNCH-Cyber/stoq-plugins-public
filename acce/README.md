# Cipher Tech Solutions ACCE (Automated Component and Configuration Extraction)

[stoQ](https://stoq-framework.readthedocs.io/en/latest/index.html) plugin that scans payloads using [ACCE](https://www.ciphertechsolutions.com/products/acce/)

ACCE is recommended to run against all files and will determine if the provided file should be processed further based on internal yara rule mappings.
ACCE quota usage is based on yara matches, so only submissions where ACCE does subsequent processing is done will be counted

Contact acce.support@ciphertechsolutions.com for questions, comments, improvements, or fixes related to this plugin or about ACCE in general

## Plugin Classes

- [Worker](https://stoq-framework.readthedocs.io/en/latest/dev/workers.html)

## Configuration

All options below may be set by:

- [plugin configuration file](https://stoq-framework.readthedocs.io/en/latest/dev/plugin_overview.html#configuration)
- [`stoq` command](https://stoq-framework.readthedocs.io/en/latest/gettingstarted.html#plugin-options)
- [`Stoq` class](https://stoq-framework.readthedocs.io/en/latest/dev/core.html?highlight=plugin_opts#using-providers)

### Options

- `acce_root_url` [str]: Base URL for ACCE instance

- `api_key` [str]: ACCE API key

- `wait_for_results` [`True`/`False`]: Wait for analysis to complete before returning results

- `delay` [int]: Time in seconds to wait between checking for completed results

- `max_attempts` [int]: Maximum number of attempts to retrieve results (ACCE is an Asynchronous processing system with it's own queueing system which may result in longer than desired wait times)

- `get_artifacts` [`True`/`False`]: Retrieve files extracted from submission during ACCE processing (this includes components extracted during processing such as droppers, loaders, implants, etc)

- `should_archive_extracted` [`True`/`False`]: Archives extracted artifacts if destination archiver is defined (requires get_artifacts to be True)

- `dispatch_extracted_to` [str]: Comma separated list of plugins to dispatch artifacts to (requires get_artifacts to be True)

- `windows_safe_encoding` [`True`/`False`]: Encodes ACCE results safely for Windows systems by replacing non cp1252 characters with unicode numbers

- `use_mwcp_legacy` [`True`/`False`]: Retrieve ACCE results with MWCP results in the legacy format (see https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP for details on the legacy format)