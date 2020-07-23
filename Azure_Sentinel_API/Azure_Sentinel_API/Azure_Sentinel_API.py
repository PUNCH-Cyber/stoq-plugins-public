
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

import json
import requests
import datetime
import hashlib
import hmac
import base64

from typing import Dict, Optional
from stoq.plugins import ConnectorPlugin
from stoq.helpers import StoqConfigParser
from stoq.data_classes import StoqResponse

class SentinelConnector(ConnectorPlugin):

    def __init__(self, config: StoqConfigParser) -> None:
        super().__init__(config)

        self.workspaceId = config.get('options', 'workspaceId', fallback=None)
        if not self.workspaceId:
            raise StoqPluginException('workspaceId has not been defined')

        self.workspaceKey = config.get('options', 'workspaceKey', fallback=None)
        if not self.workspaceKey:
            raise StoqPluginException('workspaceKey has not been defined')

        self.logType = config.get('options', 'logType', fallback=None)
        if not self.logType:
            raise StoqPluginException('LogType has not been defined')

    # Build the API signature
    def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):

        x_headers = 'x-ms-date:' + date
        string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
        bytes_to_hash = bytes(string_to_hash, encoding="utf-8")  
        decoded_key = base64.b64decode(shared_key)
        encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
        authorization = "SharedKey {}:{}".format(customer_id,encoded_hash)

        return authorization

    # Build and send a request to the POST API
    def post_data(customer_id, shared_key, body, log_type):
        method = 'POST'
        content_type = 'application/json'
        resource = '/api/logs'
        rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
        content_length = len(body)
        signature = build_signature(customer_id, shared_key, rfc1123date, content_length, method, content_type, resource)
        uri = 'https://' + customer_id + '.ods.opinsights.azure.com' + resource + '?api-version=2016-04-01'

        headers = {
            'content-type': content_type,
            'Authorization': signature,
            'Log-Type': log_type,
            'x-ms-date': rfc1123date
        }

        response = requests.post(uri,data=body, headers=headers)
        if (response.status_code >= 200 and response.status_code <= 299):
            print('Accepted')
        else:
            print("Response code: {}".format(response.status_code))

    async def save(self, response: StoqResponse) -> None:

        async with post_data(self.workspaceId, self.workspaceKey, json.dumps(str(response)), self.logType) as r:
            result = await r.text()