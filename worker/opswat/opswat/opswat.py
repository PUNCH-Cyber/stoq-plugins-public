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

Submit content to an OPSWAT Metascan server for scanning and
retrieve the results

"""

import sys
import requests
import argparse
from time import sleep

from stoq.args import StoqArgs
from stoq.plugins import StoqWorkerPlugin


class OpswatScan(StoqWorkerPlugin):

    def __init__(self):
        super().__init__()

    def activate(self, stoq):
        self.stoq = stoq

        parser = argparse.ArgumentParser()
        parser = StoqArgs(parser)
        worker_opts = parser.add_argument_group("Plugin Options")
        worker_opts.add_argument("-o", "--url",
                                 dest='url',
                                 default=None,
                                 help="Metascan API url")

        options = parser.parse_args(sys.argv[2:])
        super().activate(options=options)

        return True

    def scan(self, payload, **kwargs):
        """
        Scan a payload using OPSWAT Metascan

        :param bytes payload: Payload to be scanned
        :param **kwargs filename: Filename of payload

        :returns: Results from scan
        :rtype: dict or None

        """
        super().scan()

        headers = {}

        if 'filename' in kwargs:
            headers['filename'] = kwargs['filename']
        else:
            headers['filename'] = self.stoq.get_uuid

        try:
            headers['apikey'] = self.apikey
        except AttributeError:
            pass

        # We are going to keep retrying to submit the sample
        while True:
            try:
                result = requests.post(self.url, data=payload, headers=headers)
                break
            except:
                sleep(1)

        if result.status_code == 200:
            data_id_json = self.stoq.loads(result.content)
            return self.parse_results(data_id_json['data_id'])
        else:
            return None

    def parse_results(self, uid):
        """
        Wait for a scan to complete and then parse the results

        """
        # Keep trying to load the results until we have something.
        # This may take a few seconds to minutes, depending on the
        # file and load of the opswat server
        while True:
            try:
                url = "{}/{}".format(self.url, uid)
                raw_response = requests.get(url)
                response = self.stoq.loads(raw_response.content.decode("utf-8"))

                if response['scan_results']['progress_percentage'] is 100:
                    return response
                sleep(1)
            except:
                sleep(1)
