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

import base64
import hashlib
import googleapiclient.discovery

from io import BytesIO
from datetime import datetime
from configparser import ConfigParser
from typing import Optional, Dict
from google.cloud.storage import Blob, Client

from stoq import StoqPluginException
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

        self.project_id = config.get('options', 'project_id')
        self.archive_bucket = config.get('options', 'archive_bucket', fallback='')
        self.connector_bucket = config.get('options', 'connector_bucket', fallback='')
        self.use_sha = config.getboolean('options', 'use_sha', fallback=True)
        self.use_datetime = config.getboolean('options', 'use_datetime', fallback=False)
        self.use_encryption = config.getboolean(
            'options', 'use_encryption', fallback=False
        )
        if self.use_encryption:
            self.crypto_id = config.get('options', 'crypto_id')
            self.keyring_id = config.get('options', 'keyring_id')
            self.location_id = config.get('options', 'location_id')

            # Creates an API client for the KMS API.
            self.kms_client = googleapiclient.discovery.build(
                'cloudkms', 'v1', cache_discovery=False
            )
            self.kms_key = f'projects/{self.project_id}/locations/{self.location_id}/keyRings/{self.keyring_id}/cryptoKeys/{self.crypto_id}'

    def save(self, response: StoqResponse) -> None:
        """
        Save results to Google Cloud Storage

        """
        self._upload(str(response).encode(), response.scan_id, self.connector_bucket)

    def archive(self, payload: Payload, request_meta: RequestMeta) -> ArchiverResponse:
        """
        Archive payload to GCS

        """

        if self.use_sha:
            filename = hashlib.sha1(payload.content).hexdigest()
            filename = f'{"/".join(list(filename[:5]))}/{filename}'
        elif self.use_datetime:
            datetime_path = datetime.now().strftime('%Y/%m/%d')
            filename = f'{datetime_path}/{payload.payload_id}'
        else:
            filename = payload.payload_id
        self._upload(payload.content, filename, self.archive_bucket)
        return ArchiverResponse(
            {
                'bucketId': self.archive_bucket,
                'objectId': filename,
                'projectId': self.project_id,
            }
        )

    def get(self, task: ArchiverResponse) -> Payload:
        """
        Retrieve archived payload from gcs

        """
        meta = PayloadMeta(
            extra_data={
                'bucketId': task.results['archive_bucket'],
                'objectId': task.results['path'],
                'projectId': task.results['projectId'],
            }
        )
        client = Client(project=task.results['projectId'])
        bucket = client.get_bucket(task.results['archive_bucket'])
        blob = Blob(task.results['path'], bucket)
        content = BytesIO()
        blob.download_to_file(content)
        content.seek(0)
        data = content.read()
        if self.use_encryption:
            data = self._decrypt(data)
        return Payload(data, meta)

    def _upload(self, payload: bytes, filename: str, bucket: str) -> None:
        """
        Upload a payload to GCS

        """

        client = Client(project=self.project_id)
        bucket = client.get_bucket(bucket)
        if self.use_encryption:
            payload = self._encrypt(payload)
        content = BytesIO(payload)
        blob = Blob(filename, bucket)
        blob.upload_from_file(content)

    def _decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt an encrypted file with KMS

        """

        # Use the KMS API to decrypt the data.
        crypto_keys = self.kms_client.projects().locations().keyRings().cryptoKeys()
        request = crypto_keys.decrypt(
            name=self.kms_key,
            body={'ciphertext': base64.b64encode(ciphertext).decode('ascii')},
        )
        response = request.execute()
        return base64.b64decode(response['plaintext'].encode('ascii'))

    def _encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypts data from plaintext to ciphertext using KMS

        """

        # Use the KMS API to encrypt the data.
        crypto_keys = self.kms_client.projects().locations().keyRings().cryptoKeys()
        request = crypto_keys.encrypt(
            name=self.kms_key,
            body={'plaintext': base64.b64encode(plaintext).decode('ascii')},
        )
        response = request.execute()
        return base64.b64decode(response['ciphertext'].encode('ascii'))
