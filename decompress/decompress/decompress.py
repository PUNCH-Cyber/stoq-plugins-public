#   Copyright 2014-present PUNCH Cyber Analytics Group
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
import tempfile
from typing import Dict, List, Optional
from subprocess import Popen, PIPE, TimeoutExpired

from stoq.helpers import StoqConfigParser
from stoq.plugins import WorkerPlugin
from stoq.exceptions import StoqPluginException
from stoq import (
    Payload,
    Request,
    WorkerResponse,
    ExtractedPayload,
    PayloadMeta,
    Error,
)


class Decompress(WorkerPlugin):

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
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document': '7z',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.template': '7z',
        'application/vnd.openxmlformats-officedocument.spreadsheetm1.sheet': '7z',
        'application/vnd.openxmlformats-officedocument.spreadsheetm1.template': '7z',
        'application/vnd.openxmlformats-officedocument.presentationm1.presentation': '7z',
        'application/vnd.openxmlformats-officedocument.presentationm1.template': '7z',
        'application/vnd.openxmlformats-officedocument.presentationm1.slideshow': '7z',
    }

    ARCHIVE_CMDS = {
        '7z': '7z x -o%OUTDIR% -y -p%PASSWORD% %INFILE%',
        'gzip': 'gunzip %INFILE%',
        'tar': 'tar xf %INFILE% -C %OUTDIR%',
        'unace': 'unace x -p%PASSWORD% -y %INFILE% %OUTDIR%',
        'upx': 'upx -d %INFILE% -o %OUTDIR%/unpacked_exe',
    }

    def __init__(self, config: StoqConfigParser) -> None:
        super().__init__(config)

        self.required_workers.add('mimetype')
        self.timeout = config.getint('options', 'timeout', fallback=45)
        self.passwords = config.getlist(
            'options', 'passwords', fallback=['-', 'infected', 'password']
        )
        self.maximum_size = config.getint(
            'options', 'maximum_size', fallback=50_000_000
        )

    async def scan(self, payload: Payload, request: Request) -> WorkerResponse:
        """
        Decompress a payload

        payload.results.payload_meta:
            - passwords
            - archiver
        """

        if len(payload.content) > self.maximum_size:
            raise StoqPluginException(
                f'Compressed file too large: {len(payload.content)} > {self.maximum_size}'
            )

        archiver = None
        mimetype = None
        errors: List[Error] = []
        results: Dict = {}
        extracted: List[ExtractedPayload] = []
        passwords: List[str] = payload.results.payload_meta.extra_data.get(
            'passwords', self.passwords
        )

        # Determine the mimetype of the payload so we can identify the
        # correct archiver. This should either be based off the payload.results.payload_meta
        # (useful when payload is passed via dispatching) or via mimetype plugin
        if 'archiver' in payload.results.payload_meta.extra_data:
            if payload.results.payload_meta.extra_data['archiver'] in self.ARCHIVE_CMDS:
                archiver = self.ARCHIVE_CMDS[
                    payload.results.payload_meta.extra_data['archiver']
                ]
            else:
                raise StoqPluginException(
                    f"Unknown archive type of {payload.results.payload_meta['archiver']}"
                )
        else:
            mimetype = payload.results.workers['mimetype']['mimetype']
            if mimetype in self.ARCHIVE_MAGIC:
                archive_type = self.ARCHIVE_MAGIC[mimetype]
                if archive_type in self.ARCHIVE_CMDS:
                    archiver = self.ARCHIVE_CMDS[archive_type]
                else:
                    raise StoqPluginException(f'Unknown archive type of {archive_type}')
        if not archiver:
            raise StoqPluginException(
                f'Unable to determine archive type, mimetype: {mimetype}'
            )

        with tempfile.TemporaryDirectory() as extract_dir:
            fd, archive_file = tempfile.mkstemp(dir=extract_dir)
            with open(fd, 'xb') as f:
                f.write(payload.content)
                f.flush()
            archive_outdir = tempfile.mkdtemp(dir=extract_dir)
            for password in passwords:
                cmd = archiver.replace('%INFILE%', shlex.quote(archive_file))
                cmd = cmd.replace('%OUTDIR%', shlex.quote(archive_outdir))
                cmd = cmd.replace('%PASSWORD%', shlex.quote(password))
                p = Popen(
                    cmd.split(" "), stdout=PIPE, stderr=PIPE, universal_newlines=True
                )
                try:
                    outs, errs = p.communicate(timeout=self.timeout)
                except TimeoutExpired:
                    p.kill()
                    raise StoqPluginException('Timed out decompressing payload')
                if p.returncode == 0:
                    break

            for root, dirs, files in os.walk(archive_outdir):
                for f in files:
                    path = os.path.join(extract_dir, root, str(f))
                    if os.path.getsize(path) > self.maximum_size:
                        errors.append(
                            Error(
                                f'Extracted object is too large ({os.path.getsize(path)} > {self.maximum_size})',
                                plugin_name=self.plugin_name,
                                payload_id=payload.results.payload_id,
                            )
                        )
                        continue
                    with open(path, "rb") as extracted_file:
                        meta = PayloadMeta(extra_data={'filename': f})
                        try:
                            data = extracted_file.read()
                        except OSError as err:
                            errors.append(
                                Error(
                                    f'Unable to access extracted content: {err}',
                                    plugin_name=self.plugin_name,
                                    payload_id=payload.results.payload_id,
                                )
                            )
                            continue
                        extracted.append(ExtractedPayload(data, meta))
        return WorkerResponse(results, extracted=extracted, errors=errors)
