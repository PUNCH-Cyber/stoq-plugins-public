#   Copyright 2014-2018 PUNCH Cyber Analytics Group
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

"""
Overview
========

Extract content from a multitude of archive formats

Usage
=====

The variable ```archive_magic`` contains a ```dict()``` detailing the supported
mimetypes and their corresponding decompression utility. The ```archive_cmds```
```dict()``` contains the appropriate command line syntax that corresponds to
the mimetype. For instance, if the mimetype of a payload is *application/rar*,
the correponding application is *7z*, according to archive_magic. The *7z*
parameter will then be mapped to the correponding key in ``archive_cmds```.

```archive_cmds``` has several replacement strings that may be utilized to help
extract content appropriately.

    - %OUTDIR%   - Ensures archives are extracted into the appropriate directory
    - %PASSWORD% - Passwords will be guessed and iterated over, if the archive
                   utility supports password, this option should be used.
    - %INFILE%   - Signifies the temporary file that will be written to disk
                   so the application can access the payload.

"""

import os
import shlex
import magic
import tempfile
from configparser import ConfigParser
from typing import Dict, Optional
from subprocess import Popen, PIPE, TimeoutExpired

from stoq.plugins import WorkerPlugin
from stoq.exceptions import StoqException
from stoq import Payload, RequestMeta, WorkerResponse, ExtractedPayload, PayloadMeta


class Decompress(WorkerPlugin):
    ARCHIVE_MAGIC = {
        'application/gzip': 'gzip',
        'application/jar': '7z',
        'application/java-archive': '7z',
        'application/rar': '7z',
        'application/x-7z-compressed': '7z',
        'application/x-lzma': '7z',
        'application/x-ace': 'unace',
        'application/x-gzip': 'gzip',
        'application/x-rar': '7z',
        'application/x-tar': 'tar',
        'application/x-zip-compressed': '7z',
        'application/zip': '7z',
        'application/x-bzip2': '7z',
        'application/octet-stream': '7z',
        'application/x-dosexec': 'upx',
    }

    ARCHIVE_CMDS = {
        '7z': '7z x -o%OUTDIR% -y -p%PASSWORD% %INFILE%',
        'gzip': 'gunzip %INFILE%',
        'tar': 'tar xf %INFILE% -C %OUTDIR%',
        'unace': 'unace x -p%PASSWORD% -y %INFILE% %OUTDIR%',
        'upx': 'upx -d %INFILE% -o %OUTDIR%/unpacked_exe',
    }

    def __init__(self, config: ConfigParser, plugin_opts: Optional[Dict]) -> None:
        super().__init__(config, plugin_opts)

        if plugin_opts and 'passwords' in plugin_opts:
            self.passwords = [p.strip() for p in plugin_opts['passwords'].split(',')]
        elif config.has_option('options', 'passwords'):
            self.passwords = [
                p.strip() for p in config.get('options', 'passwords').split(',')
            ]
        else:
            self.passwords = []

        if plugin_opts and 'maximum_size' in plugin_opts:
            self.maximum_size = int(plugin_opts['maximum_size'])
        elif config.has_option('options', 'passwords'):
            self.maximum_size = int(config.get('options', 'maximum_size'))
        else:
            self.maximum_size = 50_000_000

    def scan(self, payload: Payload, request_meta: RequestMeta) -> WorkerResponse:
        """
        Decompress a payload

        request_meta:
            - passwords
            - archiver
        """

        if len(payload.content) > int(self.maximum_size):
            raise StoqException('Compressed file too large')

        archiver = None
        results = {}
        errors = []
        extracted = []
        passwords = request_meta.extra_data.get('passwords', self.passwords)
        if isinstance(passwords, str):
            passwords = [p.strip() for p in passwords.split(',')]

        # Determine the mimetype of the payload so we can identify the
        # correct archiver. This should either be based off the request_meta
        # (useful when payload is passed via dispatching) or via magic
        if 'archiver' in request_meta.extra_data:
            if request_meta.extra_data['archiver'] in self.ARCHIVE_CMDS:
                archiver = self.ARCHIVE_CMDS[request_meta.extra_data['archiver']]
            else:
                raise StoqException(
                    f"Unknown archive type of {request_meta['archiver']}"
                )
        else:
            mimetype = magic.from_buffer(payload.content, mime=True)
            if mimetype in self.ARCHIVE_MAGIC:
                archive_type = self.ARCHIVE_MAGIC[mimetype]
                if archive_type in self.ARCHIVE_CMDS:
                    archiver = self.ARCHIVE_CMDS[archive_type]
                else:
                    raise StoqException(f'Unknown archive type of {archive_type}')
        if not archiver:
            raise StoqException('Unable to determine archive type')

        with tempfile.TemporaryDirectory() as extract_dir:
            fd, archive_file = tempfile.mkstemp(dir=extract_dir)
            with open(fd, 'xb') as f:
                f.write(payload.content)
            archive_outdir = tempfile.mkdtemp(dir=extract_dir)
            for password in passwords:
                cmd = archiver.replace('%INFILE%', shlex.quote(archive_file))
                cmd = cmd.replace('%OUTDIR%', shlex.quote(archive_outdir))
                cmd = cmd.replace('%PASSWORD%', shlex.quote(password))
                cmd = cmd.split(" ")
                p = Popen(cmd, stdout=PIPE, stderr=PIPE, universal_newlines=True)
                try:
                    outs, errs = p.communicate(timeout=45)
                except TimeoutExpired:
                    p.kill()
                    raise StoqException('Timed out decompressing payload')
                if p.returncode == 0:
                    break

            for root, dirs, files in os.walk(archive_outdir):
                for f in files:
                    path = os.path.join(extract_dir, root, f)
                    try:
                        with open(path, "rb") as extracted_file:
                            meta = PayloadMeta(
                                extra_data={'filename': os.path.basename(path)}
                            )
                            extracted.append(
                                ExtractedPayload(extracted_file.read(), meta)
                            )
                    except Exception as err:
                        errors.append('Unable to access extracted content')

        return WorkerResponse(results, errors=errors, extracted=extracted)
