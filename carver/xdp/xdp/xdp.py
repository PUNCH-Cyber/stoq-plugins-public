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

Carve and decode streams from XDP documents

"""

from xml.dom.minidom import parseString
from xml.parsers.expat import ExpatError

from stoq.plugins import StoqCarverPlugin


class XDPCarver(StoqCarverPlugin):

    def __init__(self):
        super().__init__()

    def activate(self, stoq):
        self.stoq = stoq

        super().activate()

        # Attempt to load the bas64 extractor so we can use it against
        # the carved content
        try:
            self.base64 = self.stoq.load_plugin("b64", "decoder")
        except:
            self.log.error("Unable to load decoder:b64 plugin.")
            pass

    def carve(self, payload, **kwargs):
        """
        Carve and decode streams from XDP documents

        :param bytes payload: OLE Payload to be parsed
        :param **kwargs xdp_elements: Colon (:) seperated strings of XDP
                                      elements to attempt extraction from.
                                      Defaults to 'chunk'

        :returns: Carved OLE streams
        :rtype: list of tuples

        """

        results = None

        # In most cases, <chunk> is the element name we will care about,
        # but to ensure the most flexibility, we will allow additional xdp
        # element names to be defined via kwargs
        if 'xdp_elements' in kwargs:
            elements = kwargs['xdp_elements'].split(":")
        else:
            elements = ['chunk']

        try:
            parsed_xml = parseString(payload)
        except ExpatError:
            # Invalid XDP document..let's return None
            return results

        # Iterate of the element names
        for name in elements:
            dom_element = parsed_xml.getElementsByTagName(name)

            # getElementsByTageName returns a list of DOM elements
            for dom in dom_element:
                content = dom.firstChild.nodeValue
                # Remove any potential new lines
                content = content.rstrip()

                # Attempt to Base64 decode the content
                try:
                    content = self.base64.decode(content)[0][1]
                except:
                    # Silently fail and continue on
                    pass

                if not results:
                    results = []

                # Gather the metadata and content
                meta = {"size": len(content), "element_name": name}
                self.log.info("Carved XDP {} ({} bytes)".format(meta['element_name'],
                                                                meta['size']))
                results.append((meta, content))

        return results
