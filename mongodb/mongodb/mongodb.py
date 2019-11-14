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

Save results and archive payloads using MongoDB

"""

import json
from gridfs import GridFS
from pymongo import MongoClient
from pymongo.errors import (
    DuplicateKeyError,
    ServerSelectionTimeoutError,
    ConnectionFailure,
    NetworkTimeout,
)
from typing import Optional, Dict
from gridfs.errors import FileExists
from configparser import ConfigParser

from stoq.helpers import StoqConfigParser, get_sha1
from stoq.plugins import ConnectorPlugin, ArchiverPlugin
from stoq.data_classes import (
    StoqResponse,
    Payload,
    ArchiverResponse,
    Request,
    PayloadMeta,
)


class MongoDbPlugin(ArchiverPlugin, ConnectorPlugin):
    def __init__(self, config: StoqConfigParser) -> None:
        super().__init__(config)

        self.mongo_client = None

        self.mongodb_uri = config.get('options', 'mongodb_uri', fallback=None)
        self.mongodb_collection = config.get(
            'options', 'mongodb_collection', fallback='stoq'
        )

    async def save(self, response: StoqResponse) -> None:
        """
        Save results to MongoDB

        """
        self._connect_mongodb()
        result = json.loads(str(response))
        result['_id'] = result['scan_id']
        self.collection.insert(result)

    async def archive(self, payload: Payload, request: Request) -> ArchiverResponse:
        """
        Archive a payload to MongoDB

        """
        self._connect_gridfs()
        sha1 = get_sha1(payload.content)
        meta = payload.payload_meta.extra_data
        meta['_id'] = sha1
        try:
            with self.gridfs_db.new_file(**meta) as fp:
                fp.write(payload.content)
        except (DuplicateKeyError, FileExists):
            pass
        return ArchiverResponse(meta)

    async def get(self, task: ArchiverResponse) -> Optional[Payload]:
        """
        Retrieve archived payload from MongoDB

        """
        self._connect_gridfs()
        result = self.gridfs_db.get(task.results['_id'])
        if result:
            payload = result.read()
            return Payload(payload, PayloadMeta(extra_data=task.results))

    def _connect(self) -> None:
        """
        Connect to a mongodb instance

        """
        try:
            self.mongo_client.server_info()
        except (
            ConnectionFailure,
            NetworkTimeout,
            ServerSelectionTimeoutError,
            AttributeError,
        ):
            self.mongo_client = MongoClient(self.mongodb_uri)

    def _connect_gridfs(self) -> None:
        self._connect()
        self.gridfs_db = GridFS(self.mongo_client.stoq_gridfs)

    def _connect_mongodb(self) -> None:
        self._connect()
        self.mongo_db = self.mongo_client.stoq
        self.collection = self.mongo_db[self.mongodb_collection]

    def disconnect(self) -> None:
        """
        Disconnect from mongodb instance

        """
        self.mongo_client.disconnect()
