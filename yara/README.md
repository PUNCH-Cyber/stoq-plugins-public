# YARA

[stoQ](https://stoq-framework.readthedocs.io/en/latest/index.html) plugin that leverages yara for [scanning](https://stoq-framework.readthedocs.io/en/latest/dev/workers.html) and [dispatching](https://stoq-framework.readthedocs.io/en/latest/dev/dispatchers.html).

### Dispatcher XOR Key Extraction
Because YARA does not provide XOR keys when the modified xor keyword is used, this dispatcher also extracts XOR keys using a plaintext value stored in the metadata.

For metadata keys that start with `xor_plaintext_for_string_` and have a corresponding string key, XOR key extraction is attempted. 
For example, the value for metadata `xor_plaintext_for_string_this_prog` is used to extract XOR keys for matches on the `$this_prog` string in the `xor_This_program` rule in dispatcher.yar.

If the `xor_first_match` is default or True, a single byte as string ('0'-'255') is returned. 
If False, a list of tuples is returned. The tuple contains the match location, string key name, and the XOR byte(s) 
`[(78, '$this_prog', b'\x15')]`.

#### YARA Limitations
If metadata key names are duplicated in a YARA rule, only the last related metadata key is returned. 
YARA does not return some metadata strings effectively ([YARA issue #1242](https://github.com/VirusTotal/yara/issues/1242)).

## Plugin Classes

- [Worker](https://stoq-framework.readthedocs.io/en/latest/dev/workers.html)
- [Dispatcher](https://stoq-framework.readthedocs.io/en/latest/dev/dispatchers.html)

## Configuration

All options below may be set by:

- [plugin configuration file](https://stoq-framework.readthedocs.io/en/latest/dev/plugin_overview.html#configuration)
- [`stoq` command](https://stoq-framework.readthedocs.io/en/latest/gettingstarted.html#plugin-options)
- [`Stoq` class](https://stoq-framework.readthedocs.io/en/latest/dev/core.html?highlight=plugin_opts#using-providers)

### Options

- `worker_rules` [str]: Path to YARA rules for the scanning of a `Payload`

- `dispatch_rules` [str]: Path to YARA rules for dispatching a `Payload`

- `strings_limit` [int]: Limit the strings results in YARA matches

- `timeout` [int]: Time in seconds to wait for a YARA scan to complete

- `xor_first_match` [bool]: Whether this dispatcher extracts first XOR key (default) or list of XOR keys, string names, and locations

> Paths may be relative to the module, or a full path.
