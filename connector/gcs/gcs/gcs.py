#   Copyright 2014-2015 PUNCH Cyber Analytics Group
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

Sends and retrieves content from Google Cloud Storage

"""

from io import BytesIO

from googleapiclient import http, discovery
from oauth2client.client import GoogleCredentials

from stoq.scan import get_sha1, get_magic
from stoq.plugins import StoqConnectorPlugin


class GcsConnector(StoqConnectorPlugin):

    def __init__(self):
        super().__init__()

    def activate(self, stoq):
        self.stoq = stoq

        super().activate()

        self.conn = None

    def get_file(self, **kwargs):
        """
        Retrieve a file from GCS

        :param **kwargs bucket: Bucket name to be used
        :param **kwargs sha1: SHA1 hash to be used as a filename
        :param **kwargs filename: Filename of file to retrieve
        :param **kwargs index: Bucket to save content to

        :returns: Content of file retrieved
        :rtype: bytes or None

        """

        if not self.conn:
            self.connect()

        bucket = kwargs.get('index', self.bucket_name)

        for key in ('filename', 'sha1'):
            if key in kwargs:
                content = BytesIO()
                req = self.conn.objects().get_media(bucket=bucket,
                                                    object=kwargs[key])

                downloader = http.MediaIoBaseDownload(content, req)

                done = False
                while not done:
                    status, done = downloader.next_chunk()

                return content.read()

        return None

    def save(self, payload, archive=False, **kwargs):
        """
        Save results to GCS

        :param bytes payload: Content to be stored in GCS
        :param **kwargs bucket: Bucket name to be used
        :param **kwargs sha1: SHA1 hash to be used as a filename

        :returns: Filename used to save the payload
        :rtype: bytes

        """

        if not self.conn:
            self.connect()

        bucket = kwargs.get('index', self.bucket_name)
        sha1 = kwargs.get('sha1', get_sha1(payload))
        magic = get_magic(payload)

        hashpath = '/'.join(list(sha1[:5]))
        filename = "{}/{}".format(hashpath, sha1)

        body = {
            'name': filename
        }

        content = BytesIO(payload)
        media_body = http.MediaIoBaseUpload(content, magic)

        try:
            req = self.conn.objects().insert(bucket=bucket, body=body,
                                             media_body=media_body)
            resp = req.execute()
            self.stoq.log.debug(resp)
        except Exception as err:
            self.stoq.log.error("Unable to save file to GCS: {}".format(str(err)))
            return None

        return filename

    def connect(self):
        credentials = GoogleCredentials.get_application_default()
        self.conn = discovery.build('storage', 'v1', credentials=credentials)
