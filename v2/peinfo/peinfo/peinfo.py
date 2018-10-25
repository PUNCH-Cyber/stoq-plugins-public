#   Copyright 2014-2018 PUNCH Cyber Analytics Group
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

import os
import pefile
import struct
import peutils
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional
from configparser import ConfigParser
from inspect import currentframe, getframeinfo

from stoq.plugins import WorkerPlugin
from stoq import Payload, RequestMeta, WorkerResponse


class PeinfoPlugin(WorkerPlugin):
    def __init__(self, config: ConfigParser, plugin_opts: Optional[Dict]) -> None:
        super().__init__(config, plugin_opts)

        filename = getframeinfo(currentframe()).filename
        parent = Path(filename).resolve().parent

        if plugin_opts and 'peidrules' in plugin_opts:
            peidrules = plugin_opts['peidrules']
        elif config.has_option('options', 'peidrules'):
            peidrules = config.get('options', 'peidrules')
        if not os.path.isabs(peidrules):
            peidrules = os.path.join(parent, peidrules)
        self.peidrules = peidrules

    def scan(self, payload: Payload, request_meta: RequestMeta) -> WorkerResponse:
        """
        Scan a payload using pefile

        """

        pe = pefile.PE(data=payload.content)
        results = {}
        results['imphash'] = self.get_imphash(pe)
        results['compile_time'] = self.get_compiletime(pe)
        results['packer'] = self.get_packer(pe)
        results['is_packed'] = self.is_packed(pe)
        results['is_exe'] = self.is_exe(pe)
        results['is_dll'] = self.is_dll(pe)
        results['is_driver'] = self.is_driver(pe)
        results['is_valid'] = self.is_valid(pe)
        results['is_suspicious'] = self.is_suspicious(pe)
        results['machine_type'] = self.get_machinetype(pe)
        results['entrypoint'] = self.get_entrypoint(pe)
        results['section_count'] = self.get_sectioncount(pe)
        results['sections'] = self.get_sections(pe)
        results['imports'] = self.get_imports(pe)
        results['rich_header'] = self.get_rich_header(pe)
        pe.close()

        return WorkerResponse(results)

    def is_packed(self, pe):
        """
        Check if the payload is packed

        """

        try:
            return peutils.is_probably_packed(pe)
        except:
            return None

    def is_suspicious(self, pe):
        """
        Check if the payload is suspicious

        """

        try:
            return peutils.is_suspicious(pe)
        except:
            return None

    def is_valid(self, pe):
        """
        Check if the payload is valid

        """

        try:
            return peutils.is_valid(pe)
        except:
            return None

    def is_dll(self, pe):
        """
        Attempt to determine if the payload is a dll or not

        """

        try:
            return pe.is_dll()
        except:
            return None

    def is_driver(self, pe):
        """
        Attempt to determine if the payload is a driver or not

        """

        try:
            return pe.is_driver()
        except:
            return None

    def is_exe(self, pe):
        """
        Attempt to determine if the payload is an exe or not

        """

        try:
            return pe.is_exe()
        except:
            return None

    def get_machinetype(self, pe):
        """
        Determine the required machine type

        """

        try:
            return pefile.MACHINE_TYPE[pe.FILE_HEADER.Machine]
        except:
            return None

    def get_entrypoint(self, pe):
        """
        Determine the entry point

        """

        try:
            return hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        except:
            return None

    def get_packer(self, pe):
        """
        Attempt to identify PE packer

        """

        try:
            return self.signatures.match(pe, ep_only=True)
        except:
            return None

    def get_imphash(self, pe):
        """
        Calculate import hash of a payload

        """

        try:
            return pe.get_imphash()
        except:
            return None

    def get_compiletime(self, pe):
        """
        Attempt to gather the PE compiled time

        """

        try:
            return datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp)
        except:
            return None

    def get_sectioncount(self, pe):
        """
        Get section count

        """

        try:
            return pe.FILE_HEADER.NumberOfSections
        except:
            return None

    def get_sections(self, pe):
        """
        Iterate over sections and generate metadata on each

        """

        try:
            sections = []
            for sect in pe.sections:
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

    def get_imports(self, pe):
        """
        Gather imports of a payload

        """

        try:
            pe_imports = []
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for i in entry.imports:
                    r = {}
                    r['dll'] = entry.dll
                    r['name'] = i.name
                    r['addr'] = hex(i.address)
                    pe_imports.append(r)
            return pe_imports
        except:
            return None

    # http://www.ntcore.com/files/richsign.htm
    # Originally from https://github.com/crits/crits_services/blob/master/peinfo_service/__init__.py
    # Modified for use with stoQ
    def get_rich_header(self, pe):
        try:
            rich_hdr = pe.parse_rich_header()
            if not rich_hdr:
                return

            rich_hdr['checksum'] = hex(rich_hdr['checksum'])

            # Generate a signature of the block. Need to apply checksum
            # appropriately. The hash here is sha256 because others are using
            # that here.
            #
            # Most of this code was taken from pefile but modified to work
            # on the start and checksum blocks.
            try:
                rich_data = pe.get_data(0x80, 0x80)
                if len(rich_data) != 0x80:
                    return None
                data = list(struct.unpack("<32I", rich_data))
            except pefile.PEFormatError as e:
                return None

            checksum = data[1]
            headervalues = []

            for i in range(len(data) // 2):
                if data[2 * i] == 0x68636952:  # Rich
                    if data[2 * i + 1] != checksum:
                        self.log.error('Rich Header corrupted')
                    break
                headervalues += [data[2 * i] ^ checksum, data[2 * i + 1] ^ checksum]

            sha_256 = hashlib.sha256()
            for hv in headervalues:
                sha_256.update(struct.pack('<I', hv))
            rich_hdr['sha256'] = sha_256.hexdigest()

            return rich_hdr
        except:
            return None
