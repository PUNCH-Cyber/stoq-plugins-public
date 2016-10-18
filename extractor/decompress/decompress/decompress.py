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

Extract content from a multitude of archive formats

Usage
=====

The variable ```archive_magic`` contains a ```dict()``` detailing the supported
mimetypes and their corresponding decompression utility. The ```archive_cmds```
```dict()``` contains the appropriate command line syntax that corresponds to
the mimetype. For instance, if the mimetype of a payload is *application/rar*,
the correponding application is *7z*, according to archive_magic. The *7z*
parameter will then be mapped to the correponding key in ``archive_cmds```.

```archive_cmds``` has several replacement strings that may be utilized to help
extract content appropriately.

    - %OUTDIR%   - Ensures archives are extracted into the appropriate directory
    - %PASSWORD% - Passwords will be guessed and iterated over, if the archive
                   utility supports password, this option should be used.
    - %INFILE%   - Signifies the temporary file that will be written to disk
                   so the application can access the payload.

"""

import os
import shlex
import shutil
import tempfile
from subprocess import Popen, PIPE, TimeoutExpired

from stoq.scan import get_magic
from stoq.plugins import StoqExtractorPlugin

archive_magic = {
    'application/gzip': 'gzip',
    'application/java-archive': '7z',
    'application/rar': '7z',
    'application/x-7z-compressed': '7z',
    'application/x-ace': 'unace',
    'application/x-gzip': 'gzip',
    'application/x-rar': '7z',
    'application/x-tar': 'tar',
    'application/x-zip-compressed': '7z',
    'application/zip': '7z',
    'application/x-bzip2': '7z',
    'application/octet-stream': '7z'
}

archive_cmds = {
    '7z': '/usr/bin/7z x -o%OUTDIR% -y -p%PASSWORD% %INFILE%',
    'gzip': '/bin/gunzip %INFILE%',
    'tar': '/bin/tar xf %INFILE% -C %OUTDIR%',
    'unace': '/usr/bin/unace x -p%PASSWORD% -y %INFILE% %OUTDIR%'
}


class DecompressExtractor(StoqExtractorPlugin):

    def __init__(self):
        super().__init__()

    def activate(self, stoq):
        self.stoq = stoq
        super().activate()

    def extract(self, payload, **kwargs):
        """
        Decompress a payload

        :param bytes payload: Content to be decompressed
        :param str filename: Filename of compressed archive
        :param list archive_passwords: List of passwords to attempt against the archive

        :returns: Metadata and content extracted
        :rtype: list of tuples

        """

        # Make sure the payload is not larger that what is permitted
        if len(payload) > int(self.maximum_size):
            self.log.warn("Compressed file too large: {}".format(kwargs))
            return None

        if 'filename' in kwargs:
            filename = kwargs['filename']
        else:
            filename = self.stoq.get_uuid

        if 'archive_passwords' in kwargs:
            archive_passwords = kwargs['archive_passwords']
            if type(archive_passwords) is not (list, tuple):
                archive_passwords = archive_passwords.split(",")
        else:
            archive_passwords = self.password_list

        results = None

        # Determine the mimetype of the payload so we can identify the
        # correct archiver
        mimetype = get_magic(payload)
        self.log.debug("Mimetype: {}".format(mimetype))
        if mimetype in archive_magic:
            archive_type = archive_magic[mimetype]
            if archive_type in archive_cmds:
                archiver = archive_cmds[archive_type]
            else:
                self.log.warn("Unknown archive type: {}".format(archive_type))
                return None
        else:
            self.log.warn("Unknown MIME type: {}".format(mimetype))
            return None

        # Build our temporary directory and file structure
        tmp_archive_dir = tempfile.mkdtemp(dir=self.stoq.temp_dir)
        extract_dir = tmp_archive_dir
        archive_file = os.path.join(tmp_archive_dir, filename)

        with open(archive_file, "wb") as f:
            f.write(payload)

        for password in archive_passwords:
            # Check to see what kind of archive we have and build the
            # command as appropriate
            cmd = archiver.replace('%INFILE%', shlex.quote(archive_file))
            cmd = cmd.replace('%OUTDIR%', shlex.quote(extract_dir))
            cmd = cmd.replace('%PASSWORD%', shlex.quote(password))
            cmd = cmd.split(" ")

            # Start the process
            p = Popen(cmd, stdout=PIPE, stderr=PIPE, universal_newlines=True)
            try:
                # Monitor the command and wait for it to complete within a set
                # timeout
                outs, errs = p.communicate(timeout=45)
            except TimeoutExpired:
                p.kill()
                self.log.error("Timed out decompressing {}".format(archive_file))

            # Attempt to list contents of extract_dir, if files exist,
            # then let's break out of the loop and continue on
            # as it would mean the file extracted successfully
            if p.returncode == 0:
                break

        # Looks like we are ready, let's step through each file
        for root, dirs, files in os.walk(extract_dir):
            for f in files:
                # We are going to skip this file if the filename is the same as
                # our original file
                if f != filename:
                    base_path = os.path.join(extract_dir, root)
                    path = os.path.join(base_path, f)
                    extracted_filename = os.path.basename(path)

                    try:
                        # Open the file so we can return the content
                        with open(path, "rb") as extracted_file:
                            # Generate relevant metadata
                            meta = {}
                            content = extracted_file.read()
                            meta['filename'] = extracted_filename
                            meta['size'] = len(content)

                            # Since we defined results as None above, we need to
                            # ensure it is a list now that we have results
                            if not results:
                                results = []

                            # Construct our set for return
                            results.append((meta, content))

                            self.log.info("Extracted file {} ({} bytes) from "
                                          "{}".format(meta['filename'],
                                                      meta['size'],
                                                      filename))
                    except Exception as err:
                        self.log.warn("Unable to access extracted content: {}".format(err))

        # Cleanup the extracted content
        if os.path.isdir(tmp_archive_dir):
            shutil.rmtree(tmp_archive_dir)

        return results
