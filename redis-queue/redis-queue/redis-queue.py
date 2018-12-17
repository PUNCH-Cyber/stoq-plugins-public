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

Interact with Redis server for queuing

"""

import json
import redis
from queue import Queue
from configparser import ConfigParser
from typing import Dict, List, Optional

from stoq import helpers
from stoq.plugins import ConnectorPlugin, ProviderPlugin, ArchiverPlugin
from stoq.data_classes import (
    StoqResponse,
    Payload,
    PayloadMeta,
    RequestMeta,
    ArchiverResponse,
)


class RedisPlugin(ArchiverPlugin, ConnectorPlugin, ProviderPlugin):
    def __init__(self, config: ConfigParser, plugin_opts: Optional[Dict]) -> None:
        super().__init__(config, plugin_opts)

        self.redis_host = '127.0.0.1'
        self.redis_port = 6379
        self.redis_queue = 'stoq'
        self.publish_archive = True
        self.conn = None

        if plugin_opts and "publish_archive" in plugin_opts:
            self.publish_archive = bool(plugin_opts["publish_archive"])
        elif config.has_option("options", "publish_archive"):
            self.publish_archive = bool(config.get("options", "publish_archive"))

        if plugin_opts and "redis_host" in plugin_opts:
            self.redis_host = plugin_opts["redis_host"]
        elif config.has_option("options", "redis_host"):
            self.redis_host = config.get("options", "redis_host")

        if plugin_opts and "redis_port" in plugin_opts:
            self.redis_port = int(plugin_opts["redis_port"])
        elif config.has_option("options", "redis_port"):
            self.redis_port = config.get("options", "redis_port")

        if plugin_opts and "redis_queue" in plugin_opts:
            self.redis_queue = int(plugin_opts["redis_queue"])
        elif config.has_option("options", "redis_port"):
            self.redis_queue = config.get("options", "redis_queue")

    def archive(
        self, payload: Payload, request_meta: RequestMeta
    ) -> Optional[ArchiverResponse]:
        self._connect()
        self.conn.set(f'{payload.payload_id}_meta', str(payload.payload_meta))
        self.conn.set(f'{payload.payload_id}_buf', payload.content)
        self.conn.publish(self.redis_queue, payload.payload_id)
        return ArchiverResponse({'msg_id': payload.payload_id})

    def save(self, response: StoqResponse) -> None:
        """
        Save results or ArchiverResponse to redis

        """
        self._connect()
        if self.publish_archive:
            msgs: List[str] = []
            for result in response.results:
                msgs = [{k: v} for k, v in result.archivers.items()]
            for msg in msgs:
                self.conn.publish(self.redis_queue, helpers.dumps(msg))
        else:
            self.conn.set(response.scan_id, str(response))

    def ingest(self, queue: Queue) -> None:
        self._connect()
        pubsub = self.conn.pubsub(ignore_subscribe_messages=True)
        pubsub.subscribe(self.redis_queue)
        print(f'Monitoring redis queue {self.redis_queue}')
        for msg in pubsub.listen():
            data = msg['data'].decode()
            payload = self.conn.get(f'{data}_buf')
            meta = self.conn.get(f'{data}_meta')
            if meta and payload:
                meta = json.loads(meta.decode())
                queue.put(Payload(payload, payload_meta=PayloadMeta(extra_data=meta)))
                self.conn.delete(f'{meta}_buf')
                self.conn.delete(f'{meta}_meta')
            else:
                queue.put(json.loads(msg['data']))

    def _connect(self):
        if not self.conn:
            self.conn = redis.Redis(host=self.redis_host, port=self.redis_port)
