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

stoQ framework basic worker example

"""

# Required imports
import argparse

from stoq.args import StoqArgs
from stoq.plugins import StoqWorkerPlugin


class BasicWorker(StoqWorkerPlugin):

    def __init__(self):
        # In nearly all cases, we do not want to handle anything here
        super().__init__()

    # This function is required in order to initialize the worker.
    # The framework will call the activate() function upon initialization
    # and must return True in order for the framework to continue
    def activate(self, stoq):

        # Ensure the stoq object is available throughout our class
        self.stoq = stoq

        # Instantiate our workers command line argument parser
        parser = argparse.ArgumentParser()

        # Initialize the default requirements for a worker, if needed.
        parser = StoqArgs(parser)

        # Define the argparse group for this plugin
        worker_opts = parser.add_argument_group("Plugin Options")

        # Define the command line arguments for the worker
        worker_opts.add_argument("-r", "--rules",
                                 dest='rulepath',
                                 help="Path to rules file.")

        # The first command line argument is reserved for the framework.
        # The work should only parse everything after the first command
        # line argument. We must always use stoQ's argv object to ensure
        # the plugin is properly instantied whether it is imported or
        # used via a command line script
        options = parser.parse_args(self.stoq.argv[2:])

        # If we need to handle command line argument, let's pass them
        # to super().activate so they can be instantied within the worker
        super().activate(options=options)

        # Must return true, otherwise the framework believes something
        # went wrong
        return True

    # The framework will call the scan() function when it is ready to
    # scan. All of the initial functionality should reside here
    def scan(self, payload, **kwargs):
        """
        Basic scan function for example purposes. This example will return
        anything passed to it via **kwargs along with some additional
        content that will be added to it.

        :param bytes payload: Content to be analyzed
        :param **kwargs kwargs: Additional attributes the worker may require
                                can be provided to the worker as kwargs

        :returns: Example content
        :rtype: dict

        """
        # Make sure we call our super() class
        super().scan()

        # Valid logging levels are debug, info, warn, error, critical
        self.log.info("Analyzing a payload using the basicworker plugin")

        # Must return a dict
        kwargs['msg'] = "BasicWorker testing"
        kwargs['err'] = "Need more to do!"

        return kwargs
