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

Decodes and extracts information from Java Class files

"""

from typing import Dict
from javatools import unpack_class, ClassUnpackException

from stoq.plugins import WorkerPlugin
from stoq.exceptions import StoqPluginException
from stoq import Payload, Request, WorkerResponse


class JavaClassPlugin(WorkerPlugin):
    async def scan(self, payload: Payload, request: Request) -> WorkerResponse:
        """
        Decodes and extracts information from Java Class files

        """

        results: Dict = {}

        try:
            content = unpack_class(payload.content)
        except ClassUnpackException as err:
            raise StoqPluginException(f'Unable to parse payload: {err}')

        try:
            results = {
                'provided': content.get_provides(),
                'required': content.get_requires(),
                'constants': [],
            }
            for obj, _, data in content.cpool.pretty_constants():
                if len(data) <= 6:
                    continue
                constants = {}
                constants['id'] = obj
                constants['data'] = data
                results['constants'].append(constants)
        except Exception as err:
            raise StoqPluginException(f'Unable to analyze Java Class {err}')

        return WorkerResponse(results)
