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

Saves a file into a directory fireeye monitors via CIFS for analysis

"""

import os
import sys
import argparse

from stoq.args import StoqArgs
from stoq.plugins import StoqWorkerPlugin


class FireeyeScan(StoqWorkerPlugin):

    def __init__(self):
        super().__init__()

    def activate(self, stoq):

        self.stoq = stoq

        parser = argparse.ArgumentParser()
        parser = StoqArgs(parser)
        worker_opts = parser.add_argument_group("Plugin Options")
        worker_opts.add_option("-r", "--root",
                               dest='root',
                               help="Root path Fireeye shares are located")
        worker_opts.add_option("-i", "--images",
                               dest='images_list',
                               action='append',
                               help="Fireeye images that should be used. May"
                                    " be used more than once.")

        options = parser.parse_args(sys.argv[2:])

        super().activate(options=options)

        return True

    def scan(self, payload, **kwargs):
        """
        Submit a payload to Fireeye via a CIFS share point

        :param bytes payload: Payload to be scanned
        :param **kwargs images: List of images to use. The image names must be
                                the directory names on disk

        """
        super().scan()

        if kwargs['images']:
            images = kwargs['images']
        else:
            images = self.images_list

        if payload:
            for image in images:
                # Let's build the full path to save the sample to
                image_path = os.path.join(self.root, image.strip())
                image_path = os.path.join(image_path, "input")

                if os.path.isdir(image_path):
                    # Write the file to disk
                    self.stoq.write(path=image_path,
                                    payload=payload,
                                    binary=True)

