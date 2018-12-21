# OPSWAT Metascan

[stoQ](https://stoq-framework.readthedocs.io/en/latest/index.html) plugin that scans payloads using [Falcon Sandbox](https://www.crowdstrike.com/products/falcon-sandbox/)

## Plugin Classes

- [Worker](https://stoq-framework.readthedocs.io/en/latest/dev/workers.html)

## Configuration

All options below may be set by:

- [plugin configuration file](https://stoq-framework.readthedocs.io/en/latest/dev/plugin_overview.html#configuration)
- [`stoq` command](https://stoq-framework.readthedocs.io/en/latest/gettingstarted.html#plugin-options)
- [`Stoq` class](https://stoq-framework.readthedocs.io/en/latest/dev/core.html?highlight=plugin_opts#using-providers)

### Options

- `sandbox_url` [str]: URL for Falcon Sandbox

- `apikey` [str]: Falcon Sandbox API key

- `useragent` [str]: User Agent to use for request

- `wait_for_results` [`True`/`False`]: Wait for analysis to complete before returning results

- `delay` [int]: Time in seconds to wait between checking for completed results

- `max_attempts` [int]: Maximum amount of attempts to retrieve results

- `environment_id` [int]: Analysis environment to use

  > Available environments ID:
  >
  > - 300: 'Linux (Ubuntu 16.04, 64 bit)',
  > - 200: 'Android Static Analysis’,
  > - 160: 'Windows 10 64 bit’,
  > - 110: 'Windows 7 64 bit’,
  > - 100: ‘Windows 7 32 bit’
