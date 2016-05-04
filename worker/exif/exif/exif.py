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

Processes a payload using ExifTool

"""

import os
import argparse

from subprocess import check_output, CalledProcessError

from stoq.args import StoqArgs
from stoq.plugins import StoqWorkerPlugin


class ExifScan(StoqWorkerPlugin):

    def __init__(self):
        super().__init__()

    def activate(self, stoq):
        self.stoq = stoq

        parser = argparse.ArgumentParser()
        parser = StoqArgs(parser)
        worker_opts = parser.add_argument_group("Plugin Options")
        worker_opts.add_argument("-e", "--exiftool",
                                 dest='exiftool',
                                 help="Path to exiftool script")

        options = parser.parse_args(self.stoq.argv[2:])

        super().activate(options=options)

        return True

    def scan(self, payload, **kwargs):
        """
        Scan a payload using Exiftool

        :param bytes payload: Payload to be scanned
        :param **kwargs kwargs: Additional parameters (unused)

        :returns: Results from scan
        :rtype: dict or None

        """

        path = self.stoq.write(path=self.stoq.temp_dir,
                               payload=payload,
                               binary=True)

        if not os.path.isfile(self.exiftool):
            self.stoq.log.error("ExifTool does not exist at {}!".format(self.exiftool))
            return None

        try:
            exifdata = {}
            cmd = [self.exiftool, "-j", path]
            exifdata = self.stoq.loads(check_output(cmd))
            exifdata = exifdata[0]
        except CalledProcessError as err:
            try:
                exifdata = self.stoq.loads(err.output)
                exifdata = exifdata[0]
            except:
                exifdata = None
        except:
            exifdata = None

        # Cleanup and remove any tmp files written to disk
        try:
            if os.path.isfile(path):
                os.remove(path)
        except:
            self.stoq.log.warn("Unable to delete temp "
                               "file {0}".format(path))

        super().scan()

        return exifdata
