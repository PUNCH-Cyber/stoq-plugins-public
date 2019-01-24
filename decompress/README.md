# Decompress

[stoQ](https://stoq-framework.readthedocs.io/en/latest/index.html) plugin that decompresses payloads.

> Note: This plugin requires additional executables to be available, namely 7zip, unace, and upx.

## Plugin Classes

- [Worker](https://stoq-framework.readthedocs.io/en/latest/dev/workers.html)

## Configuration

All options below may be set by:

- [plugin configuration file](https://stoq-framework.readthedocs.io/en/latest/dev/plugin_overview.html#configuration)
- [`stoq` command](https://stoq-framework.readthedocs.io/en/latest/gettingstarted.html#plugin-options)
- [`Stoq` class](https://stoq-framework.readthedocs.io/en/latest/dev/core.html?highlight=plugin_opts#using-providers)

### Options

- `passwords` [str]: Ordered comma separated list of passwords used for brute forcing compressed payload (if supported)

- `maximum_size` [int]: Maximum size of payloads to process (original compressed file and extracted files)

- `timeout` [int]: How long (in seconds) to wait for decompression to finish

### Use

Multiple compression algorithms are currently supported. Due to the limitations of python compression libraries, `stoQ` leverages command line tools instead. `ARCHIVE_MAGIC` and `ARCHIVE_CMDS` can be found in `decompress.py`.

The `ARCHIVE_MAGIC` dictionary requires a `key`/`value` pair. The `key` is the mime-type of a compressed file. The `value` is the `key` located in `ARCHIVE_CMDS`.

    ARCHIVE_MAGIC = {
        'application/gzip': '7z',
        'application/jar': '7z',
        'application/java-archive': '7z',
        'application/rar': '7z',
        'application/x-7z-compressed': '7z',
        'application/x-lzma': '7z',
        'application/x-ace': 'unace',
        'application/x-gzip': '7z',
        'application/x-rar': '7z',
        'application/x-tar': '7z',
        'application/x-zip-compressed': '7z',
        'application/zip': '7z',
        'application/x-bzip2': '7z',
        'application/octet-stream': '7z',
        'application/x-dosexec': 'upx',
        'application/vnd.debian.binary-package': '7z',
        'application/vnd.ms-cab-compressed': '7z',
        'application/x-arj': '7z',
        'application/x-lha': '7z',
        'application/x-lzma': '7z',
        'application/x-rpm': '7z',
        'application/x-xz': '7z',
    }

The `ARCHIVE_CMDS` dictionary requires a `key`/`value` pair. The `key` should be a `value` from `ARCHIVE_MAGIC`. The `value` is the command that should be executed to decompress the payload.

    ARCHIVE_CMDS = {
        '7z': '7z x -o%OUTDIR% -y -p%PASSWORD% %INFILE%',
        'gzip': 'gunzip %INFILE%',
        'tar': 'tar xf %INFILE% -C %OUTDIR%',
        'unace': 'unace x -p%PASSWORD% -y %INFILE% %OUTDIR%',
        'upx': 'upx -d %INFILE% -o %OUTDIR%/unpacked_exe',
    }

Several substitutions are available for the command and must start and end with `%`.

- `%OUTDIR%`: Directory where the archive will be compressed. The plugin will handle the directory creation and cleanup.
- `%PASSWORD%`: Password from `passwords` option defined above. The plugin will iterate
  over the list until it is either exhausted, or the archive is successfully decompressed.
- `%INFILE%`: The full path to the archive file. The plugin will handle the creation and cleanup of this file.

As an example, let's use `7z`.

- `Stoq` is provided a `7z` compressed payload.
- A `stoq.data_classes.Payload` object is passed to the `decompress` plugin.
- The mime-type of `Payload.content` is identified -- in this case, it will be `application/x-7z-compressed`.
- `decompress` identifies the command that should be run is `7z`.
- `decompress` generates a random file containing `Payload.content` to disk -- in this case we will assume it is `/tmp/payload123`
- `decompress` generates a temporary %OUTDIR% directory, in this case we will assume it is `/tmp/outdir123`
- `decompress` iterates over the `passwords` provided, substituting the `7z` `value` with the command `7z x -o/tmp/outdir123 -y -ppassword1 /tmp/payload123`
- The archive file is decompressed into `/tmp/outdir123`. The `decompress` plugin then iterates over each extracted file, adding it to the `stoq.data_classes.WorkerResponse` as an `stoq.data_classes.ExtractedPayload` payload.
- Each `ExtractedPayload` is then passed back to `Stoq`, which processes them as appropriate.
