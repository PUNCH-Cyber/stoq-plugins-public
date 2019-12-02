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

Read and write data to Amazon S3

"""

import boto3
import hashlib

from io import BytesIO
from typing import Optional, Dict

from stoq.helpers import StoqConfigParser
from stoq.plugins import ConnectorPlugin, ArchiverPlugin
from stoq.data_classes import (
    StoqResponse,
    Payload,
    ArchiverResponse,
    Request,
    PayloadMeta,
)


class S3Plugin(ArchiverPlugin, ConnectorPlugin):
    def __init__(self, config: StoqConfigParser) -> None:
        super().__init__(config)

        self.client = None
        self.access_key = config.get('options', 'access_key', fallback=None)
        self.secret_key = config.get('options', 'secret_key', fallback=None)
        self.archive_bucket = config.get('options', 'archive_bucket', fallback=None)
        self.connector_bucket = config.get('options', 'connector_bucket', fallback=None)
        self.use_sha = config.getboolean('archiver', 'use_sha', fallback=True)

    async def save(self, response: StoqResponse) -> None:
        """
        Save results to S3

        """
        self._upload(str(response).encode(), response.scan_id, self.connector_bucket)

    async def archive(self, payload: Payload, request: Request) -> ArchiverResponse:
        """
        Archive payload to S3

        """
        if self.use_sha:
            filename = hashlib.sha1(payload.content).hexdigest()
            filename = f'{"/".join(list(filename[:5]))}/{filename}'
        else:
            filename = payload.results.payload_id
        self._upload(payload.content, filename, self.archive_bucket)
        return ArchiverResponse({'bucket': self.archive_bucket, 'path': filename})

    async def get(self, task: ArchiverResponse) -> Payload:
        """
        Retrieve archived payload from S3

        """
        if not self.client:
            self._get_client()
        meta = PayloadMeta(
            extra_data={'bucket': task.results['bucket'], 'path': task.results['path']}
        )
        content = self.client.get_object(
            Bucket=task.results['bucket'], Key=task.results['path']
        )['Body']
        return Payload(content.read(), meta)

    def _upload(self, payload: bytes, filename: str, bucket: str) -> None:
        if not self.client:
            self._get_client()
        content = BytesIO(payload)
        self.client.upload_fileobj(content, bucket, filename)

    def _get_client(self):
        self.client = boto3.client(
            's3',
            aws_access_key_id=self.access_key,
            aws_secret_access_key=self.secret_key,
        )
