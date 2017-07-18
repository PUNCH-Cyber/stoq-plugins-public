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

Retrieves and saves content to local disk

"""
from datetime import datetime

from stoq.scan import get_sha1
from stoq.plugins import StoqConnectorPlugin


class FileConnector(StoqConnectorPlugin):

    def __init__(self):
        super().__init__()

    def activate(self, stoq):
        self.stoq = stoq
        self.date_format = "%Y/%m/%d"

        super().activate()

    # We are just going to be a wrapper for Stoq.get_file()
    def get_file(self, **kwargs):
        """
        Retrieve a file from disk

        :param **kwargs path: Path to the file to be retrieved
        :param **kwargs url: URL of file to be retrieved

        :returns: Content of file retrieved
        :rtype: bytes or None

        """

        valid_keys = ['path', 'url']
        for key in valid_keys:
            if key in kwargs:
                return self.stoq.get_file(source=kwargs[key])

        return None

    def save(self, payload, archive=False, **kwargs):
        """
        Save results to disk

        :param str payload: Content to be saved
        :param bool archive: Is this a file that is being archived?
        :param str index: Directory name to save content to
        :param str sha1: SHA1 hash to use as a filename
        :param str filename: Filename to save the file as
        :param str path: Path where the file will be saved to
        :param bool use_date: Append current date to the path
        :param bool append: Allow append to output file?

        """

        if archive:
            filename = kwargs.get('sha1', get_sha1(payload))
            path = self.stoq.hashpath(filename)
            binary = kwargs.get('binary', True)
            append = kwargs.get('append', False)
        else:
            path = kwargs.get('path', None)

            if not path:
                index = kwargs.get('index', self.parentname)
                path = "{}/{}".format(self.stoq.results_dir, index)

            append = kwargs.get('append', False)
            filename = kwargs.get('filename', None)
            binary = kwargs.get('binary', False)

        if not binary:
            payload = self.stoq.dumps(payload, compactly=self.compactly)

            # Append a newline to the result, if we are appending to a file
            if append:
                payload += '\n'

        use_date = kwargs.get('use_date', False)
        if use_date:
            now = datetime.now().strftime(self.date_format)
            path = "{}/{}".format(path, now)

        fullpath = self.stoq.write(path=path, filename=filename, payload=payload,
                                   binary=binary, append=append)

        return fullpath
