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

Send reults to Azure Sentinel (Log Analytics Workspace) using the Azure Log Analytics API

"""

import hmac
import base64
import hashlib
import aiohttp

from datetime import datetime

from stoq import StoqResponse
from stoq.plugins import ConnectorPlugin
from stoq.helpers import StoqConfigParser
from stoq.exceptions import StoqPluginException


class SentinelConnector(ConnectorPlugin):
    API_RESOURCE = '/api/logs'
    CONTENT_TYPE = 'application/json'
    API_VERSION = '2016-04-01'

    def __init__(self, config: StoqConfigParser) -> None:
        super().__init__(config)

        self.workspaceid = config.get('options', 'workspaceid', fallback=None)
        if not self.workspaceid:
            raise StoqPluginException('workspaceid has not been defined')

        self.workspacekey = config.get('options', 'workspacekey', fallback=None)
        if not self.workspacekey:
            raise StoqPluginException('workspacekey has not been defined')

        self.logtype = config.get('options', 'logtype', fallback='stoQ')
        self.uri = f'https://{self.workspaceid}.ods.opinsights.azure.com{self.API_RESOURCE}?api-version={self.API_VERSION}'

    def build_signature(self, date, content_length):
        string_to_hash = 'POST\n'
        string_to_hash += f'{content_length}\n'
        string_to_hash += f'{self.CONTENT_TYPE}\n'
        string_to_hash += f'x-ms-date:{date}\n'
        string_to_hash += f'{self.API_RESOURCE}'

        encoded_hash = base64.b64encode(
            hmac.new(
                base64.b64decode(self.workspacekey),
                string_to_hash.encode('utf-8'),
                digestmod=hashlib.sha256,
            ).digest()
        ).decode()
        return f'SharedKey {self.workspaceid}:{encoded_hash}'

    async def save(self, response: StoqResponse) -> None:
        date = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
        content = str(response)
        content_length = len(content)
        headers = {
            'content-type': self.CONTENT_TYPE,
            'Authorization': self.build_signature(content, content_length),
            'Log-Type': self.logtype,
            'x-ms-date': date,
        }

        async with aiohttp.ClientSession(raise_for_status=True) as session:
            async with session.post(self.uri, data=content, headers=headers) as r:
                result = await r.text()
                if result:
                    self.log.debug(result)
