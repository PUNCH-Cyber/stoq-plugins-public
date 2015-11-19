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

Decrypts GnuPG encrypted content

Usage
=====

Configuration options should be updated in gpg.stoq, specifically:
    - gpg_bin
    - gpg_home
    - secret_keyring
    - public_keyring
    - passphrase
    - always_trust

A gpg_home directory must exist as defined in the gpg.stoq configuration file.
If one does not exist, it will be created along with a public and secret key
file.

"""

import os

from gnupg import GPG
from io import BytesIO

from stoq.plugins import StoqExtractorPlugin


class GpgExtractor(StoqExtractorPlugin):

    def __init__(self):
        super().__init__()

    def activate(self, stoq):
        self.stoq = stoq

        super().activate()

        if not os.path.exists(self.gpg_home):
            self.stoq.exception("GPG Home is not defined! Skipping...")

        self.gpg = GPG(gnupghome=self.gpg_home,
                       gpgbinary=self.gpg_bin,
                       keyring=self.public_keyring,
                       secret_keyring=self.secret_keyring)


    def extract(self, payload, **kwargs):
        """
        Decrypt content from provided payload

        :param bytes payload: Payload to be decrypted
        :param **kwargs kwargs: Additional attributes (unused)

        :returns: Decrypted payload
        :rtype: list of tuples

        """

        passphrase = None
        always_trust = False

        if self.passphrase:
            passphrase = self.passphrase

        if self.always_trust:
            always_trust = self.always_trust

        # Ensure the payload is a ByesIO object
        payload_object = BytesIO(payload)

        # Decrypt the payload and return a file object
        decrypted_payload = self.gpg.decrypt_file(payload_object,
                                                  passphrase=passphrase,
                                                  always_trust=always_trust)

        content = decrypted_payload.data

        if content:
            meta = {}
            meta['size'] = len(content)

            # Return the decrypted payload
            return [(meta, content)]

        else:
            self.stoq.log.error("Unable to decrypt payload: {}".format(kwargs))
            return None

