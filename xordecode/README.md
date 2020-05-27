# XORDecode

[stoQ](https://stoq-framework.readthedocs.io/en/latest/index.html) plugin that decodes XOR encoded payloads.

## Plugin Classes

- [Worker](https://stoq-framework.readthedocs.io/en/latest/dev/workers.html)

## Use

This plugin is designed to be used with Dispatching plugins that support XOR Key extraction, such as the 
[yara](https://github.com/PUNCH-Cyber/stoq-plugins-public/tree/v3/yara) plugin. Dispatchers must provide a `xorkey` key in `DispatcherResponse.meta`. This plugin will search through the `DispatcherResponse.meta` object for keys with the value of `xorkey`. Once found it will use the values in the `xorkey` in an attempt to XOR decode the payload. The `xorkey` values must be an integer, string, or a list of strings or integers. If a list is provided, this plugin will using rolling xor to decode the payload.

## Configuration and Options

No configuration options are required.
