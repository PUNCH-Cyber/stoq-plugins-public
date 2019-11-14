#   Copyright 2014-present PUNCH Cyber Analytics Group
#
#   Licensed under the Apache License, Version 2.0 (the 'License');
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an 'AS IS' BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

"""
Overview
========

Interact with Redis server for queuing

"""

import time
import json
import redis
from asyncio import Queue
from typing import Dict, List, Optional

from stoq.helpers import dumps, StoqConfigParser
from stoq.plugins import ConnectorPlugin, ProviderPlugin, ArchiverPlugin
from stoq.data_classes import (
    StoqResponse,
    Payload,
    PayloadMeta,
    Request,
    ArchiverResponse,
)


class RedisPlugin(ArchiverPlugin, ConnectorPlugin, ProviderPlugin):
    def __init__(self, config: StoqConfigParser) -> None:
        super().__init__(config)

        self.conn = None
        self.publish_archive = config.getboolean(
            'options', 'publish_archive', fallback=True
        )
        self.redis_host = config.get('options', 'redis_host', fallback='127.0.0.1')
        self.redis_port = config.getint('options', 'redis_port', fallback=6379)
        self.max_connections = config.getint('options', 'max_connections', fallback=15)
        self.redis_queue = config.get('options', 'redis_queue', fallback='stoq')

    async def archive(
        self, payload: Payload, request: Request
    ) -> Optional[ArchiverResponse]:
        self._connect()
        self.conn.set(f'{payload.payload_id}_meta', str(payload.payload_meta))
        self.conn.set(f'{payload.payload_id}_buf', payload.content)
        self.conn.rpush(self.redis_queue, payload.payload_id)
        return ArchiverResponse({'msg_id': payload.payload_id})

    async def save(self, response: StoqResponse) -> None:
        """
        Save results or ArchiverResponse to redis

        """
        self._connect()
        if self.publish_archive:
            msgs: List[str] = []
            for result in response.results:
                msgs = [{k: v} for k, v in result.archivers.items()]
            for msg in msgs:
                self.conn.rpush(self.redis_queue, dumps(msg))
        else:
            self.conn.set(response.scan_id, str(response))

    def ingest(self, queue: Queue) -> None:
        self._connect()
        self.log.info(f'Monitoring redis queue {self.redis_queue}')
        while True:
            msg = self.conn.blpop(self.redis_queue, timeout=0)
            if not msg:
                time.sleep(0.1)
                continue
            data = msg[1].decode()
            payload = self.conn.get(f'{data}_buf')
            meta = self.conn.get(f'{data}_meta')
            if meta and payload:
                meta = json.loads(meta.decode())
                queue.put(Payload(payload, payload_meta=PayloadMeta(extra_data=meta)))
                self.conn.delete(f'{meta}_buf')
                self.conn.delete(f'{meta}_meta')
            else:
                queue.put(json.loads(data))

    def _connect(self):
        if not self.conn:
            self.conn = redis.Redis(
                host=self.redis_host,
                port=self.redis_port,
                socket_keepalive=True,
                socket_timeout=300,
                connection_pool=redis.BlockingConnectionPool(
                    max_connections=self.max_connections
                ),
            )
