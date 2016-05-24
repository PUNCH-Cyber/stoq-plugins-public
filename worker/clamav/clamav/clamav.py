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

Scan content with ClamAV

"""

import time
import argparse
import pyclamd
import threading

from stoq.args import StoqArgs
from stoq.plugins import StoqWorkerPlugin


class ClamAvScan(StoqWorkerPlugin):

    def __init__(self):
        super().__init__()
        self.clamd_lock = threading.Lock()
        self.wants_heartbeat = True

    def activate(self, stoq):
        self.stoq = stoq

        parser = argparse.ArgumentParser()
        parser = StoqArgs(parser)

        options = parser.parse_args(self.stoq.argv[2:])
        super().activate(options=options)

        # Make sure our options are the proper type
        self.timeout = float(self.timeout)
        self.port = int(self.port)
        self.interval = int(self.interval)

        self._connect()

        if not self.clamd:
            return False

        return True


    def deactivate(self):
        self.heartbeat_thread.terminate()

    def scan(self, payload, **kwargs):
        """
        Scan content with ClamAV

        :param bytes payload: Payload to be scanned
        :param **kwargs kwargs: Additional arguments (unused)

        :returns: Results from scan
        :rtype: dict or None

        """

        super().scan()

        results = {}

        self.clamd_lock.acquire()
        try:
            hit = self.clamd.scan_stream(payload)
            results['sig'] = hit['stream'][1]
        except IOError as err:
            self.stoq.log.warn("Unable to scan payload: {}".format(err))
        except ValueError as err:
            self.stoq.log.warn("Payload buffer too large: {}".format(err))
        except TypeError:
            pass
        finally:
            self.clamd_lock.release()

        if results:
            return results
        else:
            return None

    def heartbeat(self):
        """
        Periodically ping the clam server to keep alive

        """

        while True:
            success = False
            self.clamd_lock.acquire()
            try:
                self.clamd.ping()
                success = True
            except AttributeError:
                success = False
            except pyclamd.ConnectionError:
                self.stoq.log.warn("Unable to connect to ClamAV. Attempting to connect.")
                success = False
            finally:
                self.clamd_lock.release()
            if not success:
                self._connect()
            time.sleep(self.interval)

    def _connect(self):
        """
        Connect to clam server

        """
        self.clamd_lock.acquire()
        if self.daemon == 'network':
            self.clamd = pyclamd.ClamdNetworkSocket(host=self.host,
                                                    port=self.port,
                                                    timeout=self.timeout)
        else:
            self.clamd = pyclamd.ClamdUnixSocket(filename=self.socket,
                                                 timeout=self.timeout)
        self.clamd_lock.release()

