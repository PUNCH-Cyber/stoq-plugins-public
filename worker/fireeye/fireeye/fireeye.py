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

Submit a file to a FireEye MAS/AX server. This supports submissions in via
two methods:
    1) Saving a file into a directory fireeye monitors via CIFS for analysis
    2) Submitting the file to the MAS/AX/CMS server via the API.

"""

import os
import argparse
import FireEyeMAS

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
        worker_opts.add_argument("-m", "--method",
                                 dest="method",
                                 choices=['API', "Fileshare"],
                                 help="Method to use to submit files. Can be "
                                       "API or Fileshare")
        worker_opts.add_argument("-i", "--images",
                                 dest='images_list',
                                 action='append',
                                 help="Fireeye images that should be used. May"
                                      " be used more than once.")
        worker_opts.add_argument("-n", "--name",
                                 dest="name",
                                 type=bool,
                                 default=False,
                                 required=False,
                                 help="preserve the original name of the file"
                                      " in the stoq framework. If set to false"
                                      " stoq will automatically generate a "
                                      " UUID for the name")
        fileshare_opts = worker_opts.add_argument_group("Fileshare",
                                                        "Fileshare options")
        fileshare_opts.add_argument("-r", "--root",
                                    dest='root',
                                    required=False,
                                    help="Root path Fireeye shares are located")
        api_opts = worker_opts.add_argument_group("API", "API options")
        api_opts.add_argument("-s", "--server",
                              dest="server",
                              required=False,
                              help="IP address or name of MAS/AX/CMS"
                                   " server.")
        api_opts.add_argument("-u", "--username",
                              dest="username",
                              required=False,
                              help="Username to use to log into MAS API")
        api_opts.add_argument("-p", "--password",
                              dest="password",
                              required=False,
                              help="Password to use to log into the "
                                   "MAS API")
        api_opts.add_argument("-s", "--ssl",
                              dest="ssl",
                              type=bool,
                              default=True,
                              require=False,
                              help="Verify SSL. Some MAS units use a "
                                   "self-signed certificate, which fails "
                                   "SSL validation. Use this option to "
                                   "turn off SSL validation.")
        api_opts.add_argument("-v", "--version",
                              dest="version",
                              required=False,
                              default="1.1.0",
                              choices=["1.0.0", "1.1.0"],
                              help="API Version to use. This is only "
                                   " used when using the API. Supported"
                                   " versions are 1.0.0 and 1.1.0 (default)")

        options = parser.parse_args(self.stoq.argv[2:])
        if options.method == "API":
            if not (options.server and options.username and options.password):
                parser.error("API option requires a server, username, "
                             "and password to be set.")
        else:
            if not options.root:
                parser.error("Fileshare option requires a filesystem root.")

        super().activate(options=options)

        return True

    def write_file_to_disk(self, images, payload, filename):
        if payload:
            for image in images:
                # Let's build the full path to save the sample to
                # one note: the image names by default are different for 
                # the filesystem vs the API. The filesystem by default
                # drops the "-" characters that are required for the API. 
                filesystem_image_name = image.replace("-", "").strip()
                image_path = os.path.join(self.root, filesystem_image_name)
                image_path = os.path.join(image_path, "input")

                if os.path.isdir(image_path):
                    # Write the file to disk
                    self.stoq.write(path=image_path,
                                    payload=payload,
                                    filename=filename,
                                    binary=True)

    def send_file_to_api(self, images, payload, filename):
        if payload:
            if self.version == "100":
                server = FireEyeMAS.FireEyeServerv100(self.server,
                                                      self.username,
                                                      self.password,
                                                      verifySSL=self.ssl)
            elif self.version == "110":
                server = FireEyeMAS.FireEyeServerv110(self.server,
                                                      self.username,
                                                      self.password,
                                                      verifySSL=self.ssl)
            # API returns an ID here that corresponds to the alertID
            # to query. Not sure how to pass that back.
            server.submitFile(payload,
                              filename,
                              profiles=images)

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
        if self.name:
            filename = self.stoq.get_uuid()
        else:
            if kwargs['path']:
                filename = kwargs['path'].split(os.path.sep)[-1]
            else:
                filename = "testfile"
        if self.method == "API":
            self.send_file_to_api(images, payload, filename)
        elif self.method == "Files":
            self.write_file_to_disk(images, payload, filename)


