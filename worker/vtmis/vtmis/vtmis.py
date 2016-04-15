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

Interact with VTMIS public and private API

"""

import argparse

from queue import Queue
from threading import Thread

from datetime import timedelta
from datetime import datetime

from stoq.args import StoqArgs
from stoq.plugins import StoqWorkerPlugin


class VtmisScan(StoqWorkerPlugin):

    def __init__(self):
        super().__init__()

    def activate(self, stoq):
        self.stoq = stoq

        # VTMIS API calls are not consistent, so let's map them out so the
        # code can be as simple as possible. The primary key below will
        # be appened to the root VTMIS API URI and the underscores ("_")
        # replaced with a "/". As an example, the key "ip-address_report"
        # will be translated as:
        # https://www.virustotal.com/vtapi/v2/ip-address/report/
        self.api_calls = {'file_report': {'key': 'resource', 'allinfo': True, 'method': 'get', 'private': False},
                          'file_behaviour': {'key': 'hash', 'allinfo': True, 'method': 'get', 'private': True},
                          'file_network-traffic': {'key': 'hash', 'allinfo': False, 'method': 'get', 'private': True},
                          'file_feed': {'key': 'package', 'allinfo': False, 'method': 'get', 'private': True},
                          'file_download': {'key': 'hash', 'allinfo': False, 'method': 'get', 'private': True},
                          'file_scan': {'key': False, 'allinfo': False, 'method': 'post', 'private': False},
                          'file_rescan': {'key': 'resource', 'allinfo': False, 'method': 'post', 'private': False},
                          'file_search': {'key': 'query', 'allinfo': False, 'method': 'get', 'private': True},
                          'file_clusters': {'key': 'date', 'allinfo': False, 'method': 'get', 'private': True},
                          'url_report': {'key': 'resource', 'allinfo': True, 'method': 'get', 'private': False},
                          'url_scan': {'key': 'url', 'allinfo': False, 'method': 'post', 'private': False},
                          'url_feed': {'key': 'package', 'allinfo': False, 'method': 'get', 'private': True},
                          'ip-address_report': {'key': 'ip', 'allinfo': False, 'method': 'get', 'private': False},
                          'domain_report': {'key': 'domain', 'allinfo': False, 'method': 'get', 'private': False},
                          'comments_get': {'key': 'resource', 'allinfo': False, 'method': 'get', 'private': True}
                         }

        parser = argparse.ArgumentParser()
        parser = StoqArgs(parser)

        worker_opts = parser.add_argument_group("Plugin Options")
        worker_opts.add_argument("-a", "--apikey",
                                 dest='apikey',
                                 help="VTMIS API Key")
        worker_opts.add_argument("-r", "--resource",
                                 dest='api_resource',
                                 default=False,
                                 help="VTMIS API Resource to interact with")
        worker_opts.add_argument("-q", "--query",
                                 dest='query_value',
                                 default=False,
                                 help="Value to query using the specified API resource")
        worker_opts.add_argument("-l", "--list",
                                 dest='list_resources',
                                 default=False,
                                 action='store_true',
                                 help="List all VTMIS API resources available")
        worker_opts.add_argument("-s", "--alerts",
                                 dest='do_alerts',
                                 default=False,
                                 action='store_true',
                                 help="Check for alerts via the API")
        worker_opts.add_argument("-d", "--download",
                                 dest='download_samples',
                                 default=self.download_samples,
                                 action='store_true',
                                 help="Download samples from alerts and file feed")
        worker_opts.add_argument("-c", "--feed-connector",
                                 dest='feed_connector',
                                 help="Connector to utilize to save original JSON feed content")
        worker_opts.add_argument("-f", "--save-feed",
                                 dest='feed_save',
                                 default=self.feed_save,
                                 action='store_true',
                                 help="Connector to utilize to save original JSON feed content")
        worker_opts.add_argument("-p", "--feed-path",
                                 dest='feed_path',
                                 help="Root path where the original JSON feed content is saved using file connector")
        worker_opts.add_argument("-m", "--max-threads",
                                 dest='max_threads',
                                 help="Max number of threads when processing feeds")


        options = parser.parse_args(self.stoq.argv[2:])

        super().activate(options=options)

        if self.list_resources:
            print("VTMIS API Resources Available:")
            for key, value in self.api_calls.items():
                print("\t- {}".format(key))
            print("\nUsage: stoq-cli.py vtmis -r file_search -q 7896b9b34bdbedbe7bdc6d446ecb09d5")
            print(" OR    stoq-cli.py vtmis -r domain_report -q www.google.com")
            exit(0)

        return True

    def scan(self, payload, **kwargs):
        """
        Interact with public and private VTMIS API

        :param **kwargs resource: VTMIS API resource to query
        :param **kwargs query: Query VTMIS for a specific item

        :returns: Results from specified API call
        :type: dict

        """

        super().scan()

        results = None

        resource = kwargs.get('resource', self.api_resource)
        query = kwargs.get('query', self.query_value)

        if not query:
            if not resource:
                resource = "file_report"
            query = kwargs.get('sha1', None)

        if resource == "alerts" or self.do_alerts:
            results = self.alerts()
        elif resource.endswith("_feed"):
            results = []
            for date in self.generate_dates(query):
                results.append(self.call_api(resource, date, payload))
        else:
            results = self.call_api(resource, query, payload)

        return results

    def call_api(self, resource, query=None, payload=None):
        # make sense of the API resource provided
        if resource in self.api_calls:
            api = self.api_calls[resource]
            # Replace any _ with / so we can build a valid URL
            uri = resource.replace("_", "/")
            url = "{}/{}".format(self.api_url, uri)
        else:
            self.stoq.log.warn("Invalid API resource:{}".format(resource))
            return None

        # Start building the parameters of our API call
        params = {'apikey': self.apikey}

        # Determine what key is required, if any
        if api['key']:
            if query:
                params[api['key']] = query

        # Some API calls provide additional context, if using the private API
        if api['allinfo']:
            params[api['allinfo']] = 1

        # Determine whether this API call requires a POST or GET, and whether
        # whether we are uploading a file or not.
        if api['method'] == 'get':
            response = self.stoq.get_file(url, params=params)
        elif api['method'] == 'post':
            if payload:
                uuid = self.stoq.get_uuid
                files = {'file': (uuid, payload)}
                response = self.stoq.post_file(url, files=files, params=params)
            else:
                response = self.stoq.post_file(url, params=params)

        if resource == 'file_download':
            return self.save_download(response)
        elif resource.endswith("_feed"):
            self.process_feed(response, resource, query)
            return True

        return self.stoq.loads(response)

    def alerts(self):
        processed_hashes = []
        ids = []
        results = []

        url = "{}{}{}&output=json".format(self.alerts_url,
                                          self.alerts_uri,
                                          self.apikey)

        response = self.stoq.get_file(source=url)
        alerts = self.stoq.loads(response)

        # Ensure we have results, otherwise just return None
        try:
            alert_list = alerts['notifications']
        except TypeError:
            return None

        for alert in alert_list:
            if alert['sha1'] not in processed_hashes:
                # Check to see if we need to download the file, if so, do it.
                if self.download_samples:
                    self.call_api('file_download', query=alert['sha1'])

                # Keep track of the hashes we've processed so we don't handle
                # dupes
                processed_hashes.append(alert['sha1'])

                results.append(alert)

            # Track the IDs so we can delete them when done
            ids.append(alert['id'])

        # Delete the alert from the feed so we don't handle it again
        self.delete_alert(ids)

        return results

    def delete_alert(self, ids):
        # Split the IDs into lists of 100, the maximum allowed per the API
        delete_ids = (ids[pos:pos + 100] for pos in range(0, len(ids), 100))

        # Construct the URL
        url = "{}{}{}".format(self.alerts_url,
                              self.delete_alerts_uri,
                              self.apikey)

        # Iterate over the lists and post the content to delete the alerts
        for delete_id in delete_ids:
            self.stoq.post_file(url=url, data=str(delete_id))

    def save_download(self, payload, filename=None, path=None, archive=True, feed=False):
        if payload and self.archive_connector and not feed:
            self.connectors[self.archive_connector].save(payload,
                                                         archive=archive,
                                                         binary=True,
                                                         path=path,
                                                         filename=filename)
        elif payload and self.feed_connector and feed:
            self.load_connector(self.feed_connector)
            self.connectors[self.feed_connector].save(payload,
                                                      archive=archive,
                                                      binary=True,
                                                      path=path,
                                                      filename=filename)
        else:
            self.stoq.log.error("No connector or payload defined. Unable to save payload.")

    def generate_dates(self, query):
        """
        Generate dates that are valid for VTMIS feeds.

        """
        current_time = datetime.now()
        if query.endswith("h"):
            max_time = int(query[:-1]) + 1
            for i in range(1, max_time):
                delta = current_time - timedelta(hours=i)
                yield delta.strftime("%Y%m%dT%H")
        elif query.endswith("m"):
            # VT recommends pulling no sooner than 5 minutes to allow for
            # processing on their side. Let's take that into consideration
            # when the user makes a call and automatically add 5 minutes.
            max_time = int(query[:-1]) + 5
            for i in range(5, max_time):
                delta = current_time - timedelta(minutes=i)
                yield delta.strftime("%Y%m%dT%H%M")
        else:
            yield query

    def process_feed(self, payload, resource, query):

        # Set saveresults to False as we don't return anything of use
        # when handling feeds. All of the results are saved outside of the
        # normal workflow.
        self.saveresults = False

        # Generate the filename
        index = "vtmis_{}".format(resource)
        filename = "{}-{}.tar.bz2".format(resource, query)

        queue = Queue()
        max_threads = int(self.max_threads)

        for i in range(max_threads):
            proc = Thread(target=self._save_feed, args=(queue, index, resource))
            proc.setDaemon(True)
            proc.start()

        # Do we want to save the raw JSON feed that is initially downloaded?
        if self.feed_save:
            self.save_download(payload, filename=filename, feed=True,
                               path=self.feed_path, archive=False)

        self.load_extractor("decompress")
        tar_files = self.extractors['decompress'].extract(payload)

        for tar_file in tar_files:
            raw_content = self.extractors['decompress'].extract(tar_file[1])

            for content in raw_content:
                lines = content[1].decode().split("\n")
                compressed_filename = content[0]['filename']
                self.stoq.log.info("Processing {} items from {}".format(len(lines), compressed_filename))
                for line in lines:
                    line = self.stoq.loads(line)
                    queue.put(line)

        queue.join()

    def _save_feed(self, queue, index, resource):
        while True:
            try:
                result = queue.get()

                # Check to see if we should download each sample file
                if self.download_samples and resource == 'file_feed':
                    file_link = result['link']
                    file_payload = self.stoq.get_file(file_link)
                    self.save_download(file_payload, archive=True)

                self.connectors[self.output_connector].save(result, index=index)
            except Exception as err:
                self.stoq.log.error("Unable to process VTMIS feed: {}".format(str(err)))
                queue.put(result)

            queue.task_done()

