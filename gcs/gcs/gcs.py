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

Read and write data to Google Cloud Storage

"""

import hashlib

from io import BytesIO
from configparser import ConfigParser
from google.cloud.storage import Blob, Client
from typing import Optional, Dict, Union

from stoq.plugins import ConnectorPlugin, ArchiverPlugin
from stoq.data_classes import (
    StoqResponse,
    Payload,
    ArchiverResponse,
    RequestMeta,
    PayloadMeta,
)


class GCSPlugin(ArchiverPlugin, ConnectorPlugin):
    def __init__(self, config: ConfigParser, plugin_opts: Optional[Dict]) -> None:
        super().__init__(config, plugin_opts)

        self.project_id = None
        self.archive_bucket = False
        self.connector_bucket = None
        self.use_sha = True

        if plugin_opts and 'project_id' in plugin_opts:
            self.project_id = plugin_opts['project_id']
        elif config.has_option('options', 'project_id'):
            self.project_id = config.get('options', 'project_id')

        if plugin_opts and 'archive_bucket' in plugin_opts:
            self.archive_bucket = plugin_opts['archive_bucket']
        elif config.has_option('options', 'archive_bucket'):
            self.archive_bucket = config.get('options', 'archive_bucket')

        if plugin_opts and 'connector_bucket' in plugin_opts:
            self.connector_bucket = plugin_opts['connector_bucket']
        elif config.has_option('options', 'connector_bucket'):
            self.connector_bucket = config.get('options', 'connector_bucket')

        if plugin_opts and 'use_sha' in plugin_opts:
            self.use_sha = plugin_opts['use_sha']
        elif config.has_option('archiver', 'use_sha'):
            self.use_sha = config.getboolean('archiver', 'use_sha')

    def save(self, response: StoqResponse) -> None:
        """
        Save results to Google Cloud Storage

        """
        self._upload(str(response).encode(), response.scan_id, self.connector_bucket)

    def archive(self, payload: Payload, request_meta: RequestMeta) -> ArchiverResponse:
        if self.use_sha:
            filename = hashlib.sha1(payload.content).hexdigest()
            filename = f'{"/".join(list(filename[:5]))}/{filename}'
        else:
            filename = payload.payload_id
        self._upload(payload.content, filename, self.archive_bucket)
        return ArchiverResponse({'bucket': self.archive_bucket, 'path': filename})

    def get(self, task: str) -> Payload:
        """
        Retrieve archived payload from gcs

        """
        meta = PayloadMeta(extra_data={'bucket': self.archive_bucket, 'path': task})
        client = Client(project=self.project_id)
        bucket = client.get_bucket(self.archive_bucket)
        blob = Blob(task, bucket)
        content = BytesIO()
        blob.download_to_file(content)
        content.seek(0)
        return Payload(content.read(), meta)

    def _upload(
        self, payload: Union[bytes, StoqResponse], filename: str, bucket: str
    ) -> None:
        client = Client(project=self.project_id)
        bucket = client.get_bucket(bucket)
        content = BytesIO(payload)
        blob = Blob(filename, bucket)
        blob.upload_from_file(content)
