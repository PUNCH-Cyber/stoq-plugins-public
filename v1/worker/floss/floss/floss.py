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

Process a file with flare-floss (https://github.com/fireeye/flare-floss)

"""

import os
import re
import argparse

from stoq.args import StoqArgs
from stoq.plugins import StoqWorkerPlugin

from subprocess import Popen, PIPE, TimeoutExpired


class FlossScan(StoqWorkerPlugin):

    def __init__(self):
        super().__init__()

    def activate(self, stoq):
        self.stoq = stoq

        parser = argparse.ArgumentParser()
        parser = StoqArgs(parser)
        worker_opts = parser.add_argument_group("Plugin Options")

        worker_opts.add_argument("-p", "--path",
                                 dest='floss_path',
                                 help="Path to FLOSS executable")

        worker_opts.add_argument("-n", "--minimum-length",
                                 dest='string_length',
                                 help="Minimum length for FLOSS string search")

        options = parser.parse_args(self.stoq.argv[2:])

        super().activate(options=options)

        return True

    def scan(self, payload, **kwargs):

        ascii_header = 'FLOSS static ASCII strings'
        utf16_header = 'FLOSS static UTF-16 strings'
        stackstr_header = 'FLOSS extracted stackstrings'
        decodestr_header = 'FLOSS decoded strings'

        header_pattern = re.compile('FLOSS (extracted|decoded) (\d+) (stackstrings|strings)')
        execution_pattern = re.compile('Finished execution after (.*)')

        # Check for FLOSS executable
        if not os.path.isfile(self.floss_path):
            self.log.error("FLOSS program does not exist at {}!".format(self.floss_path))
            return None

        # Create temp file for processing with external FLOSS executable
        target_path = self.stoq.write(path=self.stoq.temp_dir,
                                      payload=payload,
                                      binary=True)

        floss_results = {ascii_header: [],
                         utf16_header: [],
                         stackstr_header: [],
                         decodestr_header: []}

        # Build argument for minimum string length
        minimum_length = '--minimum-length={}'.format(self.string_length)

        program_arguments = [self.floss_path, minimum_length]

        if not self.static_strings:
            program_arguments.append('--no-static-strings')

        if not self.decode_strings:
            program_arguments.append('--no-decoded-strings')

        if not self.stack_strings:
            program_arguments.append('--no-stack-strings')

        program_arguments.append(target_path)

        floss_process = Popen(program_arguments, stdout=PIPE, stderr=PIPE, universal_newlines=True)

        try:
            floss_raw_output, floss_errors = floss_process.communicate(timeout=45)
        except TimeoutExpired:
            floss_process.kill()
            floss_errors = "Timed out after 45 seconds"
        else:
            current_header = ''

            for entry in floss_raw_output.split('\n'):

                if entry in floss_results:
                    current_header = entry
                else:
                    # Check for FLOSS header pattern match
                    entry_match = re.match(header_pattern, entry)

                    # Check for finished execution match
                    execution_time = re.match(execution_pattern, entry)

                    if entry_match:
                        current_header = entry_match.group(0).replace('{} '.format(entry_match.group(2)), '')
                        continue

                    if execution_time:
                        floss_results['FLOSS Execution Time'] = execution_time.group(1)
                        continue

                    if entry and current_header:
                        floss_results[current_header].append(entry.strip())

        # Placeholder for FLOSS errors
        if floss_errors:
            pass

        # Cleanup and remove any temp files written to disk
        try:
            if os.path.isfile(target_path):
                os.remove(target_path)
        except:
            self.log.warn("Unable to delete temp file {}".format(target_path))

        return floss_results
