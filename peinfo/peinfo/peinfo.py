#!/usr/bin/env python3

#   Copyright 2014-2019 PUNCH Cyber Analytics Group
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

Special Thanks
==============

Thanks to those at Facebook that provided most of the contributions for this plugin.

"""

import time
import pefile
import struct
import peutils
import hashlib
import binascii
from typing import Any, Dict, List, Optional, Tuple, Union

from stoq.data_classes import (
    ExtractedPayload,
    Payload,
    PayloadMeta,
    RequestMeta,
    WorkerResponse,
)
from stoq.plugins import WorkerPlugin


class PEInfoPlugin(WorkerPlugin):
    def scan(self, payload: Payload, request_meta: RequestMeta) -> WorkerResponse:
        pe = self._get_pe_file(payload.content)

        imports = self._get_imports(pe)
        exports = self._get_exports(pe)
        version_info = self._get_version_info(pe)
        certs = self._get_certs(pe)
        sections = self._get_section_info(pe)
        resources = self._get_resource_info(pe)
        rich_header = self._get_rich_header_hash(pe)
        imphash = self._get_imphash(pe)
        compile_time = self._get_compile_time(pe)
        tls_callbacks = self._get_tls_callbacks(pe)
        image_base = self._get_image_base(pe)
        entry_point = self._get_entry_point(pe)
        debug_info = self._get_debug_info(pe)
        is_packed = self._is_packed(pe)
        is_exe = self._is_exe(pe)
        is_dll = self._is_dll(pe)
        is_driver = self._is_driver(pe)
        is_suspicious = self._is_suspicious(pe)
        is_valid = self._is_valid(pe)

        results: Dict = {}
        extracted: List[ExtractedPayload] = []
        if imports:
            results['imports'] = imports
        if exports:
            results['exports'] = exports
        if version_info:
            results['version_info'] = version_info
        if certs:
            results['certificates'] = []
            for (cert_data, content) in certs:
                results['certificates'].append(cert_data)
                if content:
                    cert_data['filename'] = bytes(cert_data['sha256'], 'ascii')
                    extracted.append(
                        ExtractedPayload(
                            content=content,
                            payload_meta=PayloadMeta(extra_data=cert_data),
                        )
                    )
        if sections:
            results['sections'] = sections
        if resources:
            results['resources'] = []
            for (rsrc_data, content) in resources:
                results['resources'].append(rsrc_data)
                if content:
                    rsrc_data['filename'] = rsrc_data['name']
                    extracted.append(
                        ExtractedPayload(
                            content=content,
                            payload_meta=PayloadMeta(extra_data=rsrc_data),
                        )
                    )
        if rich_header:
            results['rich_header'] = rich_header
        if imphash:
            results['imphash'] = imphash
        if tls_callbacks:
            results['tls_callbacks'] = tls_callbacks
        if debug_info:
            results['debug_info'] = debug_info
        if is_packed:
            results['is_packed'] = is_packed
        if is_exe:
            results['is_exe'] = is_exe
        if is_dll:
            results['is_dll'] = is_dll
        if is_driver:
            results['is_driver'] = is_driver
        if is_suspicious:
            results['is_suspicious'] = is_suspicious
        if is_valid:
            results['is_valid'] = is_valid
        results['compile_time_epoch'] = compile_time[0]
        results['compile_time'] = compile_time[1]
        results['image_base'] = image_base
        results['entrypoint'] = entry_point

        pe.close()
        return WorkerResponse(results=results, extracted=extracted)

    def _get_pe_file(self, payload: bytes):
        return pefile.PE(data=payload)

    def _is_packed(self, pe) -> Union[bool, None]:
        """
        Check if the payload is packed

        """

        try:
            return peutils.is_probably_packed(pe)
        except:
            return None

    def _is_suspicious(self, pe) -> Union[bool, None]:
        """
        Check if the payload is suspicious

        """

        try:
            return peutils.is_suspicious(pe)
        except:
            return None

    def _is_valid(self, pe) -> Union[bool, None]:
        """
        Check if the payload is valid

        """

        try:
            return peutils.is_valid(pe)
        except:
            return None

    def _is_dll(self, pe) -> Union[bool, None]:
        """
        Attempt to determine if the payload is a dll or not

        """

        try:
            return pe.is_dll()
        except:
            return None

    def _is_driver(self, pe):
        """
        Attempt to determine if the payload is a driver or not

        """

        try:
            return pe.is_driver()
        except:
            return None

    def _is_exe(self, pe) -> Union[bool, None]:
        """
        Attempt to determine if the payload is an exe or not

        """

        try:
            return pe.is_exe()
        except:
            return None

    def _get_imports(self, pe) -> Dict[str, List[str]]:
        imports: Dict[str, List[str]] = {}
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for i in pe.DIRECTORY_ENTRY_IMPORT:
                dll = i.dll.decode(errors='ignore')
                if dll not in imports:
                    imports[dll] = []
                for t in i.imports:
                    imports[dll].append(
                        t.name.decode(errors='ignore') if t.name else str(t.ordinal)
                    )
        return imports

    def _get_exports(self, pe) -> List[str]:
        """
        Returns a list of exported function names or ordinals.

        """

        exports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for i in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if i.name:
                    exports.append(
                        i.name.decode(errors='ignore') if i.name else str(i.ordinal)
                    )
        return exports

    def _get_version_info(self, pe) -> Dict[str, str]:
        """
        Returns a dict containing key/value pairs from version info.

        """

        version_info = {}
        if hasattr(pe, 'FileInfo'):
            for finfo in pe.FileInfo:
                for entry in finfo:
                    if not hasattr(entry, 'StringTable'):
                        continue
                    for st_entry in entry.StringTable:
                        for str_entry in st_entry.entries.items():
                            key = str_entry[0].decode(errors='ignore')
                            value = str_entry[1].decode(errors='ignore')
                            version_info[key] = value

        if hasattr(pe, 'Var'):
            for entry in entry.Var:
                if not hasattr(entry, 'entry'):
                    continue
                for key, value in entry.entry.items():
                    version_info[key] = value.decode(errors='ignore')
        return version_info

    def _get_certs(self, pe) -> List[Tuple[Dict, bytes]]:
        """
        Returns a list of tuples containing certificate information and content.

        """

        certs = []
        for entry in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
            if entry.name != 'IMAGE_DIRECTORY_ENTRY_SECURITY':
                continue

            # Security Data Directory does not exist
            if entry is None:
                continue

            # Security Data Directory is null
            if entry.Size == 0 and entry.VirtualAddress == 0:
                continue

            # parse WIN_CERTIFICATE(s)
            WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002
            WIN_CERT_REVISION_1_0 = 0x100
            WIN_CERT_REVISION_2_0 = 0x200

            pData = entry.VirtualAddress
            eod = pData + entry.Size
            while (pData + 8 <= eod) and (pData + 8 <= len(pe.__data__)):
                (dwLength, wRevision, wCertificateType) = struct.unpack(
                    '<IHH', pe.__data__[pData : pData + 8]
                )
                # sanity checks
                if (
                    dwLength == 0
                    or pData + dwLength > eod
                    or wRevision not in [WIN_CERT_REVISION_1_0, WIN_CERT_REVISION_2_0]
                ):
                    break

                if (
                    wRevision == WIN_CERT_REVISION_2_0
                    and wCertificateType == WIN_CERT_TYPE_PKCS_SIGNED_DATA
                ):
                    win_certificate = pe.__data__[pData : pData + dwLength]
                    bCertificate = win_certificate[8:]
                    certs.append(
                        (
                            {
                                'sha1': hashlib.sha1(bCertificate).hexdigest(),
                                'sha256': hashlib.sha256(bCertificate).hexdigest(),
                                'md5': hashlib.md5(bCertificate).hexdigest(),
                                'revision': wRevision,
                                'cert_type': wCertificateType,
                                'entry_size': entry.Size,
                                'cert_size': dwLength,
                            },
                            bCertificate,
                        )
                    )
                # parse next cert
                pData += dwLength
        return certs

    def _parse_resource(self, type: str, entry, pe) -> Tuple[Dict, bytes]:
        sublang = pefile.get_sublang_name_for_lang(entry.data.lang, entry.data.sublang)
        rva = entry.data.struct.OffsetToData
        size = entry.data.struct.Size
        raw_data = pe.get_data(rva, size)
        metadata = {
            'type': type,
            'resource_id': entry.id,
            'resource_type': entry.data.struct.name,
            'address': rva,
            'offset': pe.get_offset_from_rva(rva),
            'sha256': hashlib.sha256(raw_data).hexdigest(),
            'sha1': hashlib.sha1(raw_data).hexdigest(),
            'md5': hashlib.md5(raw_data).hexdigest(),
            'language': pefile.LANG.get(entry.data.lang, 'unknown'),
            'sub_language': sublang,
            'size': size,
            'name': f'resource_{type}_{entry.id}',
        }
        return (metadata, raw_data)

    def _get_resource_info(self, pe) -> List[Tuple[Dict, bytes]]:
        """
        Returns a list of dicts describing the resources in the PE file.
        Each dict contains the type, resource type (e.g. RT_VERSION), ID,
        hashes, language, sublanguage, and its size in bytes. We can optionally
        also include the raw content of the resource.

        """
        resources = []
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                resource_type = pefile.RESOURCE_TYPE.get(entry.id, 'unknown')
                for e in entry.directory.entries:
                    for m in e.directory.entries:
                        resources.append(self._parse_resource(resource_type, m, pe))
        return resources

    def _get_section_info(self, pe) -> List[Dict]:
        """
        Returns a list of dicts describing the PE sections.

        """

        return [
            {
                'name': s.Name,
                'md5': s.get_hash_md5(),
                'sha1': s.get_hash_sha1(),
                'sha256': s.get_hash_sha256(),
                'virtaddr': s.VirtualAddress,
                'virtsize': s.Misc_VirtualSize,
                'raw_size': s.SizeOfRawData,
                'entropy': s.get_entropy(),
            }
            for s in pe.sections
        ]

    def _get_rich_header_hash(self, pe) -> Optional[str]:
        """
        Returns a SHA256 of the entire PE Rich Header. Note that we are not
        generating the hash over the raw data, but are instead iterating over
        the cleartext version of it. This includes the DanS and three cleared
        checksum values.

        """
        rich_header = pe.parse_rich_header()
        if rich_header:
            h = hashlib.sha256()
            h.update(b'DanS' + b'\x00' * 12)
            for value in rich_header['values']:
                h.update(struct.pack('<I', value))
            return h.hexdigest()
        return None

    def _get_imphash(self, pe) -> str:
        return pe.get_imphash()

    def _get_compile_time(self, pe) -> Tuple[int, str]:
        tstamp = pe.FILE_HEADER.TimeDateStamp
        return tstamp, time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(tstamp))

    def _get_tls_callbacks(self, pe) -> List[int]:
        callbacks = []
        if hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
            try:
                tls_addr = (
                    pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks
                    - pe.OPTIONAL_HEADER.ImageBase
                )
                for idx in range(255):
                    callback = pe.get_dword_from_data(
                        pe.get_data(tls_addr + 4 * idx, 4), 0
                    )
                    if callback == 0:
                        break
                    callbacks.append(callback)
            except Exception:
                pass
        return callbacks

    def _get_image_base(self, pe) -> Dict[str, Any]:
        base = pe.OPTIONAL_HEADER.ImageBase
        return {'image_base': base, 'image_base_string': str(hex(base))}

    def _get_entry_point(self, pe) -> Dict[str, Any]:
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        return {'entry_point': ep, 'entry_point_string': str(hex(ep))}

    def _get_debug_info(self, pe) -> List[Dict[str, Any]]:
        debug_entries: List[Dict[str, Any]] = []
        if not hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
            return debug_entries
        for debug in pe.DIRECTORY_ENTRY_DEBUG:
            if not hasattr(debug.struct, 'Type'):
                continue
            timestamp = debug.struct.TimeDateStamp
            time_string = time.strftime(
                '%Y-%m-%d %H:%M:%S', time.localtime(debug.struct.TimeDateStamp)
            )
            entry = {
                'MajorVersion': debug.struct.MajorVersion,
                'MinorVersion': debug.struct.MinorVersion,
                'SizeOfData': debug.struct.SizeOfData,
                'TimeDateStamp': timestamp,
                'TimeDateString': time_string,
                'Type': debug.struct.Type,
            }
            if debug.struct.Type == 0x0002:
                off = debug.struct.PointerToRawData
                size = debug.struct.SizeOfData
                if size < 24 or size > 0xFFFF:
                    continue
                debug_data = pe.__data__[off : off + size]
                if debug_data[:4] == b'RSDS':
                    pdb_string = debug_data[24 : size - 1]
                    entry.update(
                        {
                            'DebugSig': debug_data[:4],
                            'DebugGUID': '%s-%s-%s-%s'
                            % (
                                binascii.hexlify(debug_data[4:8]),
                                binascii.hexlify(debug_data[8:12]),
                                binascii.hexlify(debug_data[12:16]),
                                binascii.hexlify(debug_data[16:20]),
                            ),
                            'DebugAge': struct.unpack('<L', debug_data[20:24])[0],
                            'DebugPDB': pdb_string,
                        }
                    )
                elif debug_data[:4] == b'NB10':
                    pdb_string = debug_data[16 : size - 1]
                    entry.update(
                        {
                            'DebugSig': debug_data[:4],
                            'DebugTime': struct.unpack('<L', debug_data[8:12])[0],
                            'DebugAge': struct.unpack('<L', debug_data[12:16])[0],
                            'DebugPDB': pdb_string,
                        }
                    )
            debug_entries.append(entry)
        return debug_entries
