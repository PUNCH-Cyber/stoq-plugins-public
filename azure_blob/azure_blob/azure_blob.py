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

Save results and archive payloads with Azure Blob Storage

"""

import hashlib

from datetime import datetime
from azure.storage.blob.aio import BlobClient
from azure.core.exceptions import ResourceExistsError

from stoq.helpers import StoqConfigParser, dumps
from stoq.plugins import ArchiverPlugin, ConnectorPlugin
from stoq.data_classes import (
    StoqResponse,
    Payload,
    ArchiverResponse,
    Request,
    PayloadMeta,
)


class AzureBlobPlugin(ArchiverPlugin, ConnectorPlugin):
    def __init__(self, config: StoqConfigParser) -> None:
        super().__init__(config)

        self.conn_str = config.get('options', 'conn_str', fallback=None)
        if not self.conn_str:
            raise StoqPluginException('conn_str has not been defined')
        self.results_container = config.get(
            'options', 'results_container', fallback='stoq-results'
        )
        self.archive_container = config.get(
            'options', 'archive_container', fallback='stoq-archive'
        )
        self.use_sha = config.getboolean('options', 'use_sha', fallback=True)
        self.use_datetime = config.getboolean('options', 'use_datetime', fallback=False)

    async def save(self, response: StoqResponse) -> None:
        """
        Save response as Azure Blob Storage

        """
        blob_client: BlobClient = BlobClient.from_connection_string(
            conn_str=self.conn_str,
            container_name=self.results_container,
            blob_name=response.scan_id,
        )
        await blob_client.upload_blob(dumps(response))
        await blob_client.close()

    async def get(self, task: ArchiverResponse) -> Payload:
        """
        Retrieve archived payload from Azure Blob Storage

        """
        blob_client: BlobClient = BlobClient.from_connection_string(
            conn_str=self.conn_str,
            container_name=task.results['container_name'],
            blob_name=task.results['blob_name'],
        )
        content = await blob_client.download_blob()
        await blob_client.close()
        meta = PayloadMeta(task.results)
        return Payload(content.readall(), meta)

    async def archive(self, payload: Payload, request: Request) -> ArchiverResponse:
        """
        Archive payload to Azure Blob Storage

        """
        if self.use_sha:
            filename = hashlib.sha1(payload.content).hexdigest()
            filename = f'{"/".join(list(filename[:5]))}/{filename}'
        elif self.use_datetime:
            datetime_path = datetime.now().strftime('%Y/%m/%d')
            filename = f'{datetime_path}/{payload.payload_id}'
        else:
            filename = payload.results.payload_id

        blob_client: BlobClient = BlobClient.from_connection_string(
            conn_str=self.conn_str,
            container_name=self.archive_container,
            blob_name=filename,
        )
        try:
            await blob_client.upload_blob(payload.content)
        except ResourceExistsError:
            pass
        await blob_client.close()
        return ArchiverResponse(
            {'container_name': self.archive_container, 'blob_name': filename}
        )
