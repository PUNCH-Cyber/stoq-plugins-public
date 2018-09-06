#   Copyright 2014-2016 PUNCH Cyber Analytics Group
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

import argparse

from javatools import unpack_class

from stoq.args import StoqArgs
from stoq.plugins import StoqWorkerPlugin


class JavaClassWorker(StoqWorkerPlugin):

    def __init__(self):
        super().__init__()

    def activate(self, stoq):

        self.stoq = stoq

        parser = argparse.ArgumentParser()
        parser = StoqArgs(parser)

        options = parser.parse_args(self.stoq.argv[2:])

        super().activate(options=options)

        return True

    def scan(self, payload, **kwargs):
        """
        Decodes and extracts information from Java Class files

        :param bytes payload: Payload to be decoded

        :returns: Java Class Information
        :rtype: dict

        """

        results = {}

        try:
            content = unpack_class(payload)
        except Exception as err:
            self.log.error("Unable to parse payload: {}".format(err))
            return

        try:
            results['provided'] = content.get_provides()
            results['required'] = content.get_requires()
            results['constants'] = []
            for obj, _, data in content.cpool.pretty_constants():
                if len(data) <= 6:
                    continue
                constants = {}
                constants['id'] = obj
                constants['data'] = data
                results['constants'].append(constants)
        except Exception as err:
            self.log.error("Unable to analyze Java Class: {}".format(err))

        return results
