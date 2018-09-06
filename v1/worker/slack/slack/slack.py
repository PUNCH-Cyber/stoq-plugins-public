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

Interact with stoQ Plugins using Slack as an interface

"""

import os
import re
import time
import argparse
import threading
from slackclient import SlackClient

from stoq.args import StoqArgs
from stoq.plugins import StoqWorkerPlugin


class SlackWorker(StoqWorkerPlugin):

    def __init__(self):
        super().__init__()

    def activate(self, stoq):

        self.stoq = stoq

        parser = argparse.ArgumentParser()
        parser = StoqArgs(parser)

        options = parser.parse_args(self.stoq.argv[2:])

        super().activate(options=options)

        self.workers = {}

        return True

    def scan(self, payload, **kwargs):
        """
        Monitor a Slack channel for events

        """

        super().scan()

        # Connect to slack with out RTM API token
        self.slackclient = SlackClient(self.token)

        self.errors = 0
        self.time_since = 0
        thread = None

        # Connect to Slack for Real Time Messaging (RTM)
        if self.slackclient.rtm_connect():
            while True:
                try:
                    # Received event(s)
                    events = self.slackclient.rtm_read()

                    # We receive all message since the last update as a list,
                    # let's iterate over them
                    for msg in events:
                        # If we have no type, which happens for some message,
                        # let's skip this one
                        if 'type' not in msg:
                            continue
                        elif msg['type'] == 'file_shared':
                            # A file was uploaded and made public, let's handle
                            # it
                            try:
                                channel = msg['file']['channels'][0]
                            except IndexError:
                                channel = msg['file']['user']

                            thread = threading.Thread(target=self.process_payload,
                                                      args=(msg,))

                        elif msg['type'] == 'message':
                            # Received a message, let's parse it
                            channel = msg['channel']
                            thread = threading.Thread(target=self.process_message,
                                                      args=(msg,))
                        else:
                            # Carry on
                            continue

                        # Start the thread, if we have one
                        if thread:
                            thread.daemon = False
                            thread.start()

                        time.sleep(1)

                        # Let's increment our second since last error, if we
                        # have any errors that is.
                        if self.errors > 0:
                            self.time_since += 1

                except BlockingIOError:
                    # Sometimes if the worker completes after the then
                    # rtm_read() call, we end up with a BlockingIOError
                    # exception. Let's just ignore it.
                    pass
                except Exception as e:
                    self.log.error("Error handling message: {}".format(str(msg)))
                    # Looks like something is not happy, let's die so we don't
                    # make everyone hate the bot
                    if self.errors > 2 and self.time_since < 30:
                        self.send_msg(channel, "I've got a headache..I'm out.")
                        exit(-1)
                    # Reset the time since our last error, and increment our
                    # error count
                    self.time_since = 0
                    self.errors += 1
                    self.send_msg(channel, "Well crap..something went wrong.\n{}".format(str(e)))

        else:
            self.log.error("Unable to connect to Slack. Invalid token?")

    def process_payload(self, msg):
        """
        Process a file that was uploaded

        """

        # Define the parameters that we care about
        try:
            metadata = {'url': msg['file']['url_download'],
                        'filename': msg['file']['name'],
                        }
        except KeyError:
            # Looks like this isn't an upload/post that we can handle
            return

        # Check if there was a comment, if so, grab it
        if 'initial_comment' in msg['file']:
            metadata['comments'] = msg['file']['initial_comment']['comment']

        # We are going to create a list of the workers, in case we want to scan
        # with multiple workers
        workers = msg['file']['title']
        workers = [w.strip() for w in workers.split(",")]

        # Slack returns a channel list for file submissions, so there may be
        # several. We are only going to pay attention to the first one though
        channel = msg['file']['channels'][0]

        print("File uploaded! {}".format(metadata['url']))

        # Check to see if the worker defined is one we know how to handle
        for worker in workers:
            if worker not in self.plugin_list:
                # Don't know how to handle this one, remove it
                workers.remove(worker)

        # Check if we have any workers remaining, if not, we are done
        if len(workers) == 0:
            return

        self.send_msg(channel, "Scanning file...give me a moment")

        # Retrieve the file once so we can send it as many workers as needed
        payload = self.stoq.get_file(metadata['url'])

        # Normalize the user info and then save the info so we know who
        # submitted what
        userinfo = self.get_user_info(msg['file']['user'])
        userinfo = self.normalize_user_info(userinfo)

        # Merge metadata with our updated userinfo
        metadata.update(userinfo)

        # Let's archive the payload now, if needed, rather than having the
        # worker archive it. Otherwise it will be done multiple times
        if self.archive_connector:
            self.save_payload(payload, self.archive_connector)

        # Iterate over the worker plugins and send the results back as they
        # are completed
        for worker in workers:
            # Make sure we load the worker plugin, if we haven't already
            self.load_worker(worker)

            # The output_connector is going to be False by default. Set it
            # to what was defined when the slack plugin was instantiated
            self.workers[worker].output_connector = self.output_connector

            # Handle the payload with the worker
            results = self.workers[worker].start(
                payload, template=self.template, **metadata)

            self.send_msg(channel, results)

    def process_message(self, msg):
        """
        Process a message that begin with a !

        """

        try:
            channel = msg['channel']
            user = msg['user']
            text = msg['text'].rstrip()
        except KeyError:
            # This is not a message we care about
            return

        # Log conversations, if a connector is defined
        if self.conversation_connector:
            # Ensure the connector is loaded
            self.load_connector(self.conversation_connector)

            # Get the user's info so we can provide some context
            userinfo = self.get_user_info(user)
            userinfo = self.normalize_user_info(userinfo)
            msg.update(userinfo)

            # Save the content to the connector
            try:
                self.connectors[self.conversation_connector].save(msg)
            except Exception as err:
                self.log.error("Unable to log conversation: {}".format(str(err)))

        self.log.info("New message from {}: {}".format(user, text))

        # Check if the message starts with our command character
        if text.startswith(self.command_character):
            # It does, let's split the message by whitespace
            match = re.split("\s", text)

            if match[0] == "!help":
                self.print_help(channel)
                return

            # The length must be more than 2, otherwise we will ignore
            # the message
            if len(match) != 3:
                return

            # Define the worker and remove the leading command character
            worker = match[0].lstrip(self.command_character)

            # This doesn't appear to be for use, carry on
            if worker not in self.plugin_list:
                return

            # The second word should be our command
            command = match[1]

            # The last value should be the value that processed by the worker
            value = match[2]

            # Let's define the payload, we don't absolutely need this for
            # the worker
            payload = None

            # Slack parses out links, so www.google.com would look like
            # <http://www.google.com|www.google.com>. This will strip out
            # www.google.com and any additional parameters after it, then merge
            # them so we can pass the full message onto the worker
            value_matches = re.search(r"<.*\|(.*)>(.*)", value)
            if value_matches:
                value = "{} {}".format(value_matches.group(1),
                                       value_matches.group(2)).rstrip()

            # Make sure the encoding is correct
            # value = value.encode("utf-8")

            if command == "rescan":
                payload = self.get_payload(value)

                if not payload:
                    self.send_msg(channel, "I don't seem to have that sample.")
                    return

            # Load our worker, if we haven't already
            self.load_worker(worker)

            # Let's define the kwargs to pass to the worker, which must know
            # how to handle them
            kwargs = {command: value}

            # Pass our content to the worker
            results = self.workers[worker].start(
                payload, template=self.template, **kwargs)

            self.send_msg(channel, results)

    def get_payload(self, value):
        # See if the user wants us to rescan a file based on
        # md5/sha1/sha256 hash
        hash_matches = re.search("^([a-fA-F0-9]{32}$|[a-fA-F0-9]{40}$|[a-fA-F0-9]{60}$)", value)

        # Let's continue on if it is not a valid hash
        if not hash_matches:
            return

        hashes = hash_matches.group(0)

        # If the connector we want to retrieve the file from is local,
        # let's handle that a bit differently.
        if self.archive_connector == "file":
            path = os.path.join(self.stoq.hashpath(hashes), hashes)
            return self.stoq.get_file(path)
        else:
            # Setup our key values so we pass the right hash type to
            # the connector
            hash_keys = {32: 'md5',
                         40: 'sha1',
                         60: 'sha256'}

            hashargs = {hash_keys[len(hashes)]: hashes}
            return self.connectors[self.archive_connector].get_file(**hashargs)

    def get_user_info(self, id):
        """
        Returns detailed information about the user

        """
        # Use Slack's user.info API call to gather information on the user
        # that submitted the file
        userinfo = self.slackclient.api_call("users.info", **{'user': id})
        if type(userinfo) is not dict:
            userinfo = self.stoq.loads(userinfo)

        # If an error was produced, return that instead
        if 'error' in userinfo:
            return userinfo['error']

        return userinfo

    def normalize_user_info(self, userinfo):
        """
        Extract only the keys we care about so we can track who submits what

        """

        user = {}
        user_keys = ['id', 'name']
        profile_keys = ['real_name', 'email']

        for k in user_keys:
            if k in userinfo['user']:
                user[k] = userinfo['user'][k]

        for k in profile_keys:
            if k in userinfo['user']['profile']:
                user[k] = userinfo['user']['profile'][k]

        return user

    def send_msg(self, channel, msg):
        """
        Send a message to a specific channel or user

        """

        # The max size for a message to slack is 4000 bytes, let's ensure that
        # we don't send any larger than that
        msg_size = 4000

        if type(msg) is dict:
            # The content is a dict, let's prettify it
            msg = str(self.stoq.dumps(msg))

        # Ensure our max message size is 4000 bytes, then sleep for 1 second to
        # prevent being banned
        for i in range(0, len(msg), msg_size):
            msg_slice = msg[i:i+msg_size]
            self.slackclient.rtm_send_message(channel, msg_slice)
            time.sleep(1)

    def print_help(self, channel):
        """
        Print a help msg to the channel or user

        """

        msg = "Upload a file for scanning and then use one or more of the\n"
        msg += "following keywords in the title box seperated by a comma:\n"
        for p in self.plugin_list:
            msg += "    {}\n".format(p)

        msg += "\nYou may also scan a file again, or with another plugin by\n"
        msg += "specifying the md5, sha1, or sha256 hash. For example:\n"
        msg += "!yara rescan 12bf0190f3369dbb418278c93332016c\n"
        msg += "\nGive it a go."

        self.send_msg(channel, msg)
