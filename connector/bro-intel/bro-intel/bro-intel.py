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

Save output from iocextract worker plugin formatted for Bro Intel Framework

"""

import os

from stoq.plugins import StoqConnectorPlugin


class BroIntelConnector(StoqConnectorPlugin):

    def __init__(self):
        super().__init__()

    def activate(self, stoq):
        self.stoq = stoq

        self.intel_types = {'ipv4': 'Intel::ADDR',
                            'email': 'Intel:EMAIL',
                            'domain': 'Intel::DOMAIN',
                            'md5': 'Intel::FILE_HASH',
                            'sha1': 'Intel::FILE_HASH',
                            'sha256': 'Intel::FILE_HASH',
                            'sha512': 'Intel::FILE_HASH',
                            'uri': 'Intel::URL'
                            }

        self.intel_header = "#fields"
        self.intel_header += "\tindicator"
        self.intel_header += "\tindicator_type"
        self.intel_header += "\tmeta.source"
        self.intel_header += "\tmeta.desc"
        self.intel_header += "\n"

        super().activate()

    def save(self, payload, archive=False, **kwargs):
        """
        Save iocextract plugin reults to Bro Intel Framework

        :param dict payload: iocextract results
        :param bool archive: Unused
        :param **kwargs intel_filename: Filename to save the results to

        """

        intel_filename = kwargs.get('intel_filename', self.intel_filename)

        # Check to see if the intel framework file exists, if not, create it
        # and then write the header
        fullpath = os.path.abspath(intel_filename) 
        filename = os.path.basename(fullpath)
        path = os.path.dirname(fullpath)
        if not os.path.exists(fullpath):
            self.stoq.write(self.intel_header, path=path, filename=filename)

        meta_date = payload['date']

        for result in payload['results']:
            meta_filename = result['filename']
            meta_uuid = result['uuid']
            for k, v in result['scan'].items():
                intel_type = self.intel_types.get(k)
                if intel_type:
                    for indicator in v:
                        intel_output = "{}".format(indicator)
                        intel_output += "\t{}".format(intel_type)
                        intel_output += "\t{}".format(meta_filename)
                        intel_output += "\tdate:{} uuid:{}".format(meta_date, meta_uuid)
                        intel_output += "\n"

                        self.stoq.write(intel_output, path=path, filename=filename, append=True)

        self.stoq.log.info("Saving file to disk: {}".format(fullpath))

        return True

