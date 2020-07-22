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

Handle file and directory interactions

"""

import os
import hashlib

from pathlib import Path
from asyncio import Queue
from datetime import datetime

from stoq import helpers
from stoq.helpers import StoqConfigParser
from stoq.exceptions import StoqPluginException
from stoq.plugins import ProviderPlugin, ConnectorPlugin, ArchiverPlugin
from stoq import Payload, PayloadMeta, ArchiverResponse, StoqResponse, Request


class FileDirPlugin(ProviderPlugin, ConnectorPlugin, ArchiverPlugin):
    def __init__(self, config: StoqConfigParser) -> None:
        super().__init__(config)

        self.source_dir = config.get('options', 'source_dir', fallback=None)
        self.recursive = config.getboolean('options', 'recursive', fallback=False)
        self.results_dir = config.get(
            'options', 'results_dir', fallback=os.path.join(os.getcwd(), 'results')
        )
        self.date_mode = config.getboolean('options', 'date_mode', fallback=False)
        self.date_format = config.get('options', 'date_format', fallback='%Y/%m/%d')
        self.compactly = config.getboolean('options', 'compactly', fallback=True)
        self.archive_dir = config.get(
            'options', 'archive_dir', fallback=os.path.join(os.getcwd(), 'archive')
        )
        self.use_sha = config.getboolean('options', 'use_sha', fallback=True)

    async def ingest(self, queue: Queue) -> None:
        """
        Ingest files from a directory

        """
        if not self.source_dir:
            raise StoqPluginException('Source directory not defined')
        source_path = Path(self.source_dir).resolve()
        if source_path.is_dir():
            if self.recursive:
                for path in source_path.rglob('**/*'):
                    await self._queue(path, queue)
            else:
                for path in source_path.glob('*'):
                    await self._queue(path, queue)
        else:
            await self._queue(source_path, queue)

    async def _queue(self, path: Path, queue: Queue) -> None:
        """
        Publish payload to stoQ queue

        """
        if path.is_file() and not path.name.startswith('.'):
            meta = PayloadMeta(
                extra_data={
                    'filename': str(path.name),
                    'source_dir': str(path.parent),
                }
            )
            with open(path, "rb") as f:
                await queue.put(Payload(f.read(), meta))
        else:
            self.log.debug(f'Skipping {path}, does not exist or is invalid')

    async def save(self, response: StoqResponse) -> None:
        """
        Save results to disk

        """

        path = Path(self.results_dir).resolve()
        if self.date_mode:
            now = datetime.now().strftime(self.date_format)
            path = path.joinpath(now)
        path.mkdir(parents=True, exist_ok=True)

        filename = response.scan_id
        with open(path.joinpath(filename), 'x') as outfile:
            outfile.write(f'{helpers.dumps(response, compactly=self.compactly)}\n')

    async def archive(self, payload: Payload, request: Request) -> ArchiverResponse:
        """
        Archive payload to disk

        """
        path = Path(self.archive_dir).resolve()
        filename = payload.results.payload_id
        if self.use_sha:
            filename = hashlib.sha1(payload.content).hexdigest()
            path = path.joinpath("/".join(list(filename[:5])))
        elif self.date_mode:
            now = datetime.now().strftime(self.date_format)
            path = path.joinpath(now)
        path.mkdir(parents=True, exist_ok=True)
        try:
            with open(path.joinpath(filename), 'xb') as outfile:
                outfile.write(payload.content)
        except FileExistsError:
            pass
        return ArchiverResponse({'path': str(path.joinpath(filename))})

    async def get(self, task: ArchiverResponse) -> Payload:
        """
        Retrieve archived payload from disk

        """
        path = Path(task.results['path']).resolve()
        meta = PayloadMeta(extra_data=task.results)
        self.log.debug(f'got task: {task}, path: {path}, meta: {meta}')
        with open(path, 'rb') as f:
            return Payload(f.read(), meta)
