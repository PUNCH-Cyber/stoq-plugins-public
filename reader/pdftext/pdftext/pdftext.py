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

Extract text from a PDF document

"""

from io import BytesIO
from PyPDF2 import PdfFileReader

from stoq.plugins import StoqReaderPlugin


class PDFTextReader(StoqReaderPlugin):

    def __init__(self):
        super().__init__()

    def activate(self, stoq):
        self.stoq = stoq
        super().activate()

    def read(self, payload, **kwargs):
        """
        Extract text from a PDF file

        :param bytes payload : Contents of pdf file
        :param **kwargs kwargs: Additional attributes (unused)

        :returns: Extracted content of payload
        :rtype: bytes

        """

        # Ensure the payload if a ByesIO object
        payload_object = BytesIO(payload)

        # Parse the PDF payload
        pdf_object = PdfFileReader(payload_object, strict=False)

        results = []

        # Determine if the pdf is encrypted, if so, let's attempt to decrypt
        if pdf_object.isEncrypted:
            try:
                # Returns 0 if the password failed, 1 if the password matched
                # the user password, and 2 if the password matched the owner
                # password.
                decrypt_return = pdf_object.decrypt(kwargs['pdf_password'])
                if decrypt_return == 0:
                    self.stoq.log.warn("Incorrect PDF encryption password")
            except NotImplementedError:
                self.stoq.log.warn("Unsupported encryption method")
            except:
                self.stoq.log.error("Unable to decrypt PDF. Was a password provided?")

        # Iterate over the pages and append to our 
        for page in pdf_object.pages:
            results.append(page.extractText())

        return "".join(results)
