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

Gather relevant information about an executable using pefile

"""

import sys
import argparse
import peutils
import pefile

from datetime import datetime

from stoq.args import StoqArgs
from stoq.plugins import StoqWorkerPlugin


class PEInfoScan(StoqWorkerPlugin):

    def __init__(self):
        super().__init__()

    def activate(self, stoq):

        self.stoq = stoq

        parser = argparse.ArgumentParser()
        parser = StoqArgs(parser)

        worker_opts = parser.add_argument_group("Plugin Options")
        worker_opts.add_argument("-r", "--peidrules",
                                 dest="peidrules",
                                 help="Path to peid rules file")

        options = parser.parse_args(sys.argv[2:])
        super().activate(options=options)

        self.signatures = peutils.SignatureDatabase(self.peidrules)

        return True

    def scan(self, payload, **kwargs):
        """
        Scan a payload using pefile

        :param bytes payload: Payload to be scanned
        :param **kwargs kwargs: Additional parameters (unused)

        :returns: Results from scan
        :rtype: dict or None

        """

        super().scan()

        # Gather peinfo using peutils and pefile
        self.pe_open(payload)

        # Let's create our results if pefile was successful
        if self.pe:
            results = {}
            results['imphash'] = self.get_imphash()
            results['compile_time'] = self.get_compiletime()
            results['packer'] = self.get_packer()
            results['is_packed'] = self.is_packed()
            results['is_exe'] = self.is_exe()
            results['is_dll'] = self.is_dll()
            results['is_driver'] = self.is_driver()
            results['is_valid'] = self.is_valid()
            results['is_suspicious'] = self.is_suspicious()
            results['machine_type'] = self.get_machinetype()
            results['entrypoint'] = self.get_entrypoint()
            results['section_count'] = self.get_sectioncount()
            results['sections'] = self.get_sections()
            results['imports'] = self.get_imports()

            # self.pe must be closed when done otherwise you may be in store
            # for an unpleasant memory leak.
            self.pe_close()

            return results

        # Not a PE, return none
        return None

    def pe_open(self, payload):
        """
        Open a file using pefile library

        """

        try:
            self.pe = pefile.PE(data=payload)
        except pefile.PEFormatError:
            self.pe = None

    def pe_close(self):
        """
        Close pefile object

        """
        try:
            self.pe.close()
        except:
            pass

    def is_packed(self):
        """
        Check if the payload is packed

        """

        try:
            return peutils.is_probably_packed(self.pe)
        except:
            return None

    def is_suspicious(self):
        """
        Check if the payload is suspicious

        """

        try:
            return peutils.is_suspicious(self.pe)
        except:
            return None

    def is_valid(self):
        """
        Check if the payload is valid

        """

        try:
            return peutils.is_valid(self.pe)
        except:
            return None

    def is_dll(self):
        """
        Attempt to determine if the payload is a dll or not

        """

        try:
            return self.pe.is_dll()
        except:
            return None

    def is_driver(self):
        """
        Attempt to determine if the payload is a driver or not

        """

        try:
            return self.pe.is_driver()
        except:
            return None

    def is_exe(self):
        """
        Attempt to determine if the payload is an exe or not

        """

        try:
            return self.pe.is_exe()
        except:
            return None

    def get_machinetype(self):
        """
        Determine the required machine type

        """

        try:
            return pefile.MACHINE_TYPE[self.pe.FILE_HEADER.Machine]
        except:
            return None

    def get_entrypoint(self):
        """
        Determine the entry point

        """

        try:
            return hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        except:
            return None

    def get_packer(self):
        """
        Attempt to identify PE packer

        """

        try:
            return self.signatures.match(self.pe, ep_only=True)
        except:
            return None

    def get_imphash(self):
        """
        Calculate import hash of a payload

        """

        try:
            return self.pe.get_imphash()
        except:
            return None

    def get_compiletime(self):
        """
        Attempt to gather the PE compiled time

        """

        try:
            return datetime.fromtimestamp(self.pe.FILE_HEADER.TimeDateStamp)
        except:
            return None

    def get_sectioncount(self):
        """
        Get section count

        """

        try:
            return self.pe.FILE_HEADER.NumberOfSections
        except:
            return None

    def get_sections(self):
        """
        Iterate over sections and generate metadata on each

        """

        try:
            sections = []
            for sect in self.pe.sections:
                sect_dict = {}
                # Ensure the null byte padding is removed
                sect_dict['name'] = sect.Name.replace(b'\x00', b'').decode()
                sect_dict['entropy'] = sect.get_entropy()
                sect_dict['virt_addr'] = hex(sect.VirtualAddress)
                sect_dict['virt_size'] = hex(sect.Misc_VirtualSize)
                sect_dict['raw_size'] = sect.SizeOfRawData
                sect_dict['md5'] = sect.get_hash_md5()
                sect_dict['sha1'] = sect.get_hash_sha1()
                sect_dict['sha256'] = sect.get_hash_sha256()
                sect_dict['sha512'] = sect.get_hash_sha512()
                sections.append(sect_dict)
            return sections
        except:
            return None

    def get_imports(self):
        """
        Gather imports of a payload

        """

        try:
            pe_imports = []
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                for i in entry.imports:
                    r = {}
                    r['dll'] = entry.dll
                    r['name'] = i.name
                    r['addr'] = hex(i.address)
                    pe_imports.append(r)
            return pe_imports
        except:
            return None


