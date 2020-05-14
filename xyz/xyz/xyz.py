#!/usr/bin/env python3

#   Copyright 2014-present PUNCH Cyber Analytics Group
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
#
# Copyright 2020 National Technology & Engineering Solutions of Sandia, LLC (NTESS).
# Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains certain rights in this software.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# (MIT license)
#
# This software also incorporates some Python Software Foundation License code
#

"""
Overview
========

Extract Zip file metadata

Thanks
======

Thanks to National Technology & Engineering Solutions of Sandia and Charles Smutz for authoring and open sourcing the original code
https://github.com/sandialabs/xyz

Note
====

This version has been modified from the original to work with the stoQ framework as well as python 3.6+

"""

import zlib
import struct
import zipfile
import binascii
import datetime

from io import BytesIO

from stoq.plugins import WorkerPlugin
from stoq.helpers import StoqConfigParser
from stoq import Payload, Request, WorkerResponse


'''
   From Zip specification, https://www.loc.gov/preservation/digital/formats/digformatspecs/APPNOTE(20120901)_Version_6.3.3.txt

   4.4.5 compression method: (2 bytes)

        0 - The file is stored (no compression)
        1 - The file is Shrunk
        2 - The file is Reduced with compression factor 1
        3 - The file is Reduced with compression factor 2
        4 - The file is Reduced with compression factor 3
        5 - The file is Reduced with compression factor 4
        6 - The file is Imploded
        7 - Reserved for Tokenizing compression algorithm
        8 - The file is Deflated
        9 - Enhanced Deflating using Deflate64(tm)
       10 - PKWARE Data Compression Library Imploding (old IBM TERSE)
       11 - Reserved by PKWARE
       12 - File is compressed using BZIP2 algorithm
       13 - Reserved by PKWARE
       14 - LZMA (EFS)
       15 - Reserved by PKWARE
       16 - Reserved by PKWARE
       17 - Reserved by PKWARE
       18 - File is compressed using IBM TERSE (new)
       19 - IBM LZ77 z Architecture (PFS)
       97 - WavPack compressed data
       98 - PPMd version I, Rev 1
'''

method = {
    0: "store",
    1: "shrunk",
    2: "reduce1",
    3: "reduce2",
    4: "reduce3",
    5: "reduce4",
    6: "implode",
    7: "token",
    8: "deflate",
    9: "deflate64",
    10: "terse_old",
    12: "bzip2",
    14: "lzma",
    18: "terse_new",
    19: "lz77",
    97: "wavpack",
    98: "ppmd",
    99: "aes",
}


'''
       0 - MS-DOS and OS/2 (FAT / VFAT / FAT32 file systems)
         1 - Amiga                     2 - OpenVMS
         3 - UNIX                      4 - VM/CMS
         5 - Atari ST                  6 - OS/2 H.P.F.S.
         7 - Macintosh                 8 - Z-System
         9 - CP/M                     10 - Windows NTFS
        11 - MVS (OS/390 - Z/OS)      12 - VSE
        13 - Acorn Risc               14 - VFAT
        15 - alternate MVS            16 - BeOS
        17 - Tandem                   18 - OS/400
        19 - OS X (Darwin)            20 thru 255 - unused
'''

create_software = {
    0: "FAT",
    1: "Amiga",
    2: "OpenVMS",
    3: "UNIX",
    4: "VM/CMS",
    5: "Atari",
    6: "HPFS",
    7: "Mac",
    8: "Z-System",
    9: "CP/M",
    10: "NTFS",
    11: "MVS",
    12: "VSE",
    13: "Acorn",
    14: "VFAT",
    15: "alt MVS",
    16: "BeOS",
    17: "Tandem",
    18: "OS/400",
    19: "OSX",
}

'''
   4.4.4 general purpose bit flag: (2 bytes)

        Bit 0: If set, indicates that the file is encrypted.

        (For Method 6 - Imploding)
        Bit 1: If the compression method used was type 6,
               Imploding, then this bit, if set, indicates
               an 8K sliding dictionary was used.  If clear,
               then a 4K sliding dictionary was used.

        Bit 2: If the compression method used was type 6,
               Imploding, then this bit, if set, indicates
               3 Shannon-Fano trees were used to encode the
               sliding dictionary output.  If clear, then 2
               Shannon-Fano trees were used.

        (For Methods 8 and 9 - Deflating)
        Bit 2  Bit 1
          0      0    Normal (-en) compression option was used.
          0      1    Maximum (-exx/-ex) compression option was used.
          1      0    Fast (-ef) compression option was used.
          1      1    Super Fast (-es) compression option was used.

        (For Method 14 - LZMA)
        Bit 1: If the compression method used was type 14,
               LZMA, then this bit, if set, indicates
               an end-of-stream (EOS) marker is used to
               mark the end of the compressed data stream.
               If clear, then an EOS marker is not present
               and the compressed data size must be known
               to extract.

        Note:  Bits 1 and 2 are undefined if the compression
               method is any other.

        Bit 3: If this bit is set, the fields crc-32, compressed
               size and uncompressed size are set to zero in the
               local header.  The correct values are put in the
               data descriptor immediately following the compressed
               data.  (Note: PKZIP version 2.04g for DOS only
               recognizes this bit for method 8 compression, newer
               versions of PKZIP recognize this bit for any
               compression method.)

        Bit 4: Reserved for use with method 8, for enhanced
               deflating.

        Bit 5: If this bit is set, this indicates that the file is
               compressed patched data.  (Note: Requires PKZIP
               version 2.70 or greater)

        Bit 6: Strong encryption.  If this bit is set, you MUST
               set the version needed to extract value to at least
               50 and you MUST also set bit 0.  If AES encryption
               is used, the version needed to extract value MUST
               be at least 51. See the section describing the Strong
               Encryption Specification for details.  Refer to the
               section in this document entitled "Incorporating PKWARE
               Proprietary Technology into Your Product" for more
               information.

        Bit 7: Currently unused.

        Bit 8: Currently unused.

        Bit 9: Currently unused.

        Bit 10: Currently unused.

        Bit 11: Language encoding flag (EFS).  If this bit is set,
                the filename and comment fields for this file
                MUST be encoded using UTF-8. (see APPENDIX D)

        Bit 12: Reserved by PKWARE for enhanced compression.

        Bit 13: Set when encrypting the Central Directory to indicate
                selected data values in the Local Header are masked to
                hide their actual values.  See the section describing
                the Strong Encryption Specification for details.  Refer
                to the section in this document entitled "Incorporating
                PKWARE Proprietary Technology into Your Product" for
                more information.

        Bit 14: Reserved by PKWARE.

        Bit 15: Reserved by PKWARE.
'''

flags_short = {
    "encrypted": "e",
    "implode_8k": "8",
    "implode_4k": "4",
    "implode_3trees": "3",
    "implode_2trees": "2",
    "deflate_superfast": "S",
    "deflate_fast": "F",
    "deflate_max": "M",
    "deflate_normal": "N",
    "lzma_eos": "E",
    "lzma_size": "Z",
    "descriptor": "d",
    "deflate_enhanced": "D",
    "patched": "p",
    "strong_encrypt": "s",
    "utf8": "u",
    "dir_masked": "m",
}


def label_flags_short(flags_list):
    return "".join([flags_short[f] for f in flags_list])


def label_flags(bitflags, method):
    flags = []
    if bitflags & 0x0001:
        flags.append("encrypted")
    # implode
    if method == 6:
        if bitflags & 0x0002:
            flags.append("implode_8k")
        else:
            flags.append("implode_4k")
        if bitflags & 0x0004:
            flags.append("implode_3trees")
        else:
            flags.append("implode_2trees")
    if method == 8 or method == 9:
        if bitflags & 0x0004:
            if bitflags & 0x0002:
                flags.append("deflate_superfast")
            else:
                flags.append("deflate_fast")
        else:
            if bitflags & 0x0002:
                flags.append("deflate_max")
            else:
                flags.append("deflate_normal")
    if method == 14:
        if bitflags & 0x0002:
            flags.append("lzma_eos")
        else:
            flags.append("lzma_size")

    if bitflags & 0x0008:
        flags.append("descriptor")
    if bitflags & 0x0010:
        flags.append("deflate_enhanced")
    if bitflags & 0x0020:
        flags.append("patched")
    if bitflags & 0x0040:
        flags.append("strong_encrypt")
    if bitflags & 0x0800:
        flags.append("utf8")
    if bitflags & 0x0200:
        flags.append("dir_masked")

    return flags


def label_create_software(id):
    return create_software.get(id, 'unknown')


def label_method(id):
    return method.get(id, 'unknown')


compress_flags_short = {
    "deflate_nocompress": "n",
    "deflate_fixed": "f",
    "deflate_dynamic": "d",
    "deflate_reserved": "r",
    "deflate_lastblock": "l",
    "deflate_moreblocks": "m",
}


def label_compress_flags_short(flags_list):
    return "".join([compress_flags_short[f] for f in flags_list])


def label_compress_flags(data, method, flags):
    data_meta = []
    if data:
        if method == 8 and not (flags & 0x0001):
            if data[0] & 0x06 == 0x00:
                data_meta.append("deflate_nocompress")
            if data[0] & 0x06 == 0x02:
                data_meta.append("deflate_fixed")
            if data[0] & 0x06 == 0x04:
                data_meta.append("deflate_dynamic")
            if data[0] & 0x06 == 0x06:
                data_meta.append("deflate_reserved")

            if data[0] & 0x01:
                data_meta.append("deflate_lastblock")
            else:
                data_meta.append("deflate_moreblocks")

    return data_meta


'''
      internal file attributes: (2 bytes)

          The lowest bit of this field indicates, if set, that
          the file is apparently an ASCII or text file.  If not
          set, that the file apparently contains binary data.
          The remaining bits are unused in version 1.0.

          Bits 1 and 2 are reserved for use by PKWARE.
'''


def search_deflate_level(compressed_data, orig_data=None):
    '''
        Tries delate levels on orig_data, which is the decompressed data, matching level to len(compressed_size)

        returns highest level where re-compressed data is larger or equal to compressed_size, lowest level with same compression, size at that level, and Boolean indicating exact match (connanical zlib)

    '''
    compressed_size = len(compressed_data)

    if orig_data == None:
        orig_data = zlib.decompress(compressed_data)

    for level in [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]:
        compressor = zlib.compressobj(level, zlib.DEFLATED, -15)
        recompressed_data = compressor.compress(orig_data)
        recompressed_tail = compressor.flush()
        recompressed_data = recompressed_data + recompressed_tail
        recompressed_size = len(recompressed_data)
        if compressed_size <= recompressed_size:
            break

    # check for lower compression levels that compress to same size
    level2 = 0
    for level2 in range(level - 1, -1, -1):
        compressor = zlib.compressobj(level2, zlib.DEFLATED, -15)
        recompressed_data2 = compressor.compress(orig_data)
        recompressed_tail2 = compressor.flush()
        recompressed_data2 = recompressed_data2 + recompressed_tail2
        if recompressed_data != recompressed_data2:
            level2 = level2 + 1
            break

    if recompressed_data == compressed_data:
        same = True
    else:
        same = False
    return level, level2, recompressed_size, same


def label_internal_attributes(attr):
    if attr & 0x0001:
        return "text"
    else:
        return "bin"


'''
https://msdn.microsoft.com/en-us/library/windows/desktop/gg258117(v=vs.85).aspx

Let-     Bit
ter    masks Description and notes
--- -------- ---------------------------------------------------------------
 R       0x1 Read-only
 H       0x2 Hidden
 S       0x4 System
(V)      0x8 Volume label (obsolete in NTFS and must not be set)
 D      0x10 Directory
 A      0x20 Archive
 X      0x40 Device (reserved by system and must not be set)
 N      0x80 Normal (i.e. no other attributes set)
 T     0x100 Temporary
 P     0x200 Sparse file
 L     0x400 Symbolic link / Junction / Mount point / has a reparse point
 C     0x800 Compressed
 O    0x1000 Offline
 I    0x2000 Not content indexed (shown as 'N' in Explorer in Windows Vista)
 E    0x4000 Encrypted
'''

attributes_dos_short = {
    "ro": "R",
    "hidden": "H",
    "sys": "S",
    "volume": "V",
    "dir": "D",
    "archive": "A",
    "device": "X",
    "normal": "N",
    "temp": "T",
    "sparse": "P",
    "link": "L",
    "compressed": "C",
    "offline": "O",
    "not_indexed": "I",
    "encrypted": "E",
}


def label_external_attributes_dos_short(attr_list):
    return "".join([attributes_dos_short[a] for a in attr_list])


def label_external_attributes_dos(attr):
    a = []
    if attr & 0x01:
        a.append("ro")
    if attr & 0x02:
        a.append("hidden")
    if attr & 0x04:
        a.append("sys")
    if attr & 0x08:
        a.append("volume")
    if attr & 0x10:
        a.append("dir")
    if attr & 0x20:
        a.append("archive")
    if attr & 0x40:
        a.append("device")
    if attr & 0x80:
        a.append("normal")
    if attr & 0x0100:
        a.append("temp")
    if attr & 0x0200:
        a.append("sparse")
    if attr & 0x0400:
        a.append("link")
    if attr & 0x0800:
        a.append("compressed")
    if attr & 0x1000:
        a.append("offline")
    if attr & 0x2000:
        a.append("not_indexed")
    if attr & 0x4000:
        a.append("encrypted")
    return a


'''
https://unix.stackexchange.com/questions/14705/the-zip-formats-external-file-attribute
'''


'''
from python 3 Lib/stat.py

begin Python Software Foundation License code

Copyright 2001-2020 Python Software Foundation; All Rights Reserved

'''
S_IFDIR = 0o040000  # directory
S_IFCHR = 0o020000  # character device
S_IFBLK = 0o060000  # block device
S_IFREG = 0o100000  # regular file
S_IFIFO = 0o010000  # fifo (named pipe)
S_IFLNK = 0o120000  # symbolic link
S_IFSOCK = 0o140000  # socket file

S_ISUID = 0o4000  # set UID bit
S_ISGID = 0o2000  # set GID bit
S_ENFMT = S_ISGID  # file locking enforcement
S_ISVTX = 0o1000  # sticky bit
S_IREAD = 0o0400  # Unix V7 synonym for S_IRUSR
S_IWRITE = 0o0200  # Unix V7 synonym for S_IWUSR
S_IEXEC = 0o0100  # Unix V7 synonym for S_IXUSR
S_IRWXU = 0o0700  # mask for owner permissions
S_IRUSR = 0o0400  # read by owner
S_IWUSR = 0o0200  # write by owner
S_IXUSR = 0o0100  # execute by owner
S_IRWXG = 0o0070  # mask for group permissions
S_IRGRP = 0o0040  # read by group
S_IWGRP = 0o0020  # write by group
S_IXGRP = 0o0010  # execute by group
S_IRWXO = 0o0007  # mask for others (not in group) permissions
S_IROTH = 0o0004  # read by others
S_IWOTH = 0o0002  # write by others
S_IXOTH = 0o0001  # execute by others

_filemode_table = (
    (
        (S_IFLNK, "l"),
        (S_IFREG, "-"),
        (S_IFBLK, "b"),
        (S_IFDIR, "d"),
        (S_IFCHR, "c"),
        (S_IFIFO, "p"),
    ),
    ((S_IRUSR, "r"),),
    ((S_IWUSR, "w"),),
    ((S_IXUSR | S_ISUID, "s"), (S_ISUID, "S"), (S_IXUSR, "x")),
    ((S_IRGRP, "r"),),
    ((S_IWGRP, "w"),),
    ((S_IXGRP | S_ISGID, "s"), (S_ISGID, "S"), (S_IXGRP, "x")),
    ((S_IROTH, "r"),),
    ((S_IWOTH, "w"),),
    ((S_IXOTH | S_ISVTX, "t"), (S_ISVTX, "T"), (S_IXOTH, "x")),
)


def filemode(mode):
    """Convert a file's mode to a string of the form '-rwxrwxrwx'."""
    perm = []
    for table in _filemode_table:
        for bit, char in table:
            if mode & bit == bit:
                perm.append(char)
                break
        else:
            perm.append("-")
    return "".join(perm)


'''
End Python Software Foundation License code
'''


def label_external_attributes_posix(attr):
    return filemode(attr >> 16)


'''
      external file attributes: (4 bytes)

          The mapping of the external attributes is
          host-system dependent (see 'version made by').  For
          MS-DOS, the low order byte is the MS-DOS directory
          attribute byte.  If input came from standard input, this
          field is set to zero.
'''


'''
extra field documentation:

https://fossies.org/linux/zip/proginfo/extrafld.txt
https://opensource.apple.com/source/zip/zip-6/unzip/unzip/proginfo/extra.fld
AkpSigner.java



         -Extended Timestamp Extra Field:
          ==============================

          The following is the layout of the extended-timestamp extra block.
          (Last Revision 19970118)

          Local-header version:

          Value         Size        Description
          -----         ----        -----------
  (time)  0x5455        Short       tag for this extra block type ("UT")
          TSize         Short       total data size for this block
          Flags         Byte        info bits
          (ModTime)     Long        time of last modification (UTC/GMT)
          (AcTime)      Long        time of last access (UTC/GMT)
          (CrTime)      Long        time of original creation (UTC/GMT)

          Central-header version:

          Value         Size        Description
          -----         ----        -----------
  (time)  0x5455        Short       tag for this extra block type ("UT")
          TSize         Short       total data size for this block
          Flags         Byte        info bits (refers to local header!)
          (ModTime)     Long        time of last modification (UTC/GMT)

          The central-header extra field contains the modification time only,
          or no timestamp at all.  TSize is used to flag its presence or
          absence.  But note:

              If "Flags" indicates that Modtime is present in the local header
              field, it MUST be present in the central header field, too!
              This correspondence is required because the modification time
              value may be used to support trans-timezone freshening and
              updating operations with zip archives.

          The time values are in standard Unix signed-long format, indicating
          the number of seconds since 1 January 1970 00:00:00.  The times
          are relative to Coordinated Universal Time (UTC), also sometimes
          referred to as Greenwich Mean Time (GMT).  To convert to local time,
          the software must know the local timezone offset from UTC/GMT.

          The lower three bits of Flags in both headers indicate which time-
          stamps are present in the LOCAL extra field:

                bit 0           if set, modification time is present
                bit 1           if set, access time is present
                bit 2           if set, creation time is present
                bits 3-7        reserved for additional timestamps; not set

          Those times that are present will appear in the order indicated, but
          any combination of times may be omitted.  (Creation time may be
          present without access time, for example.)  TSize should equal
          (1 + 4*(number of set bits in Flags)), as the block is currently
          defined.  Other timestamps may be added in the future.



 1339          -Info-ZIP New Unix Extra Field:
 1340           ====================================
 1341
 1342           Currently stores Unix UIDs/GIDs up to 32 bits.
 1343           (Last Revision 20080509)
 1344
 1345           Value         Size        Description
 1346           -----         ----        -----------
 1347   (UnixN) 0x7875        Short       tag for this extra block type ("ux")
 1348           TSize         Short       total data size for this block
 1349           Version       1 byte      version of this extra field, currently 1
 1350           UIDSize       1 byte      Size of UID field
 1351           UID           Variable    UID for this entry
 1352           GIDSize       1 byte      Size of GID field
 1353           GID           Variable    GID for this entry
 1354
 1355           Currently Version is set to the number 1.  If there is a need
 1356           to change this field, the version will be incremented.  Changes
 1357           may not be backward compatible so this extra field should not be
 1358           used if the version is not recognized.
 1359
 1360           UIDSize is the size of the UID field in bytes.  This size should
 1361           match the size of the UID field on the target OS.
 1362
 1363           UID is the UID for this entry in standard little endian format.
 1364
 1365           GIDSize is the size of the GID field in bytes.  This size should
 1366           match the size of the GID field on the target OS.
 1367
 1368           GID is the GID for this entry in standard little endian format.
 1369
 1370           If both the old 16-bit Unix extra field (tag 0x7855, Info-ZIP Unix)
 1371           and this extra field are present, the values in this extra field
 1372           supercede the values in that extra field.




'''


known_extra_types = {
    "0001": "zip64",
    "000a": "ntfs",
    "5455": "time",
    "7875": "unix",
    "d935": "android",
    "a220": "ms_pad",
    "9901": "aes",
}


def parse_extra_data(data, type):
    tuples = []
    tokens = []
    data_len = len(data)
    # zip64
    if type == "0001":
        if data_len >= 8:
            tuples.append(('zip64_u_size', struct.unpack("<Q", data[0:8])[0]))
            tokens.append((binascii.hexlify(data[0:8])))
        if data_len >= 16:
            tuples.append(('zip64_c_size', struct.unpack("<Q", data[8:16])[0]))
            tokens.append((binascii.hexlify(data[8:16])))
        if data_len >= 24:
            tuples.append(('zip64_local_offset', struct.unpack("<Q", data[16:24])[0]))
            tokens.append((binascii.hexlify(data[16:24])))
        if data_len >= 28:
            tuples.append(('zip64_volume', struct.unpack("<L", data[24:28])[0]))
            tokens.append((binascii.hexlify(data[24:28])))
    if type == "000a":
        if data_len >= 32 and data[:8] == b'\x00\x00\x00\x00\x01\x00\x18\x00':
            tuples.append(('ntfs_reserved', ""))
            tokens.append((binascii.hexlify(data[0:4])))
            tuples.append(('ntfs_attr_type', "1"))
            tokens.append((binascii.hexlify(data[4:6])))
            tuples.append(('ntfs_attr_size', "24"))
            tokens.append((binascii.hexlify(data[6:8])))
            tuples.append(
                (
                    'ntfs_mtime',
                    (
                        datetime.datetime(1601, 1, 1, 0, 0, 0)
                        + datetime.timedelta(
                            microseconds=struct.unpack("<Q", data[8:16])[0] / 10
                        )
                    ).isoformat(),
                )
            )
            tokens.append((binascii.hexlify(data[8:16])))
            tuples.append(
                (
                    'ntfs_atime',
                    (
                        datetime.datetime(1601, 1, 1, 0, 0, 0)
                        + datetime.timedelta(
                            microseconds=struct.unpack("<Q", data[16:24])[0] / 10
                        )
                    ).isoformat(),
                )
            )
            tokens.append((binascii.hexlify(data[16:24])))
            tuples.append(
                (
                    'ntfs_ctime',
                    (
                        datetime.datetime(1601, 1, 1, 0, 0, 0)
                        + datetime.timedelta(
                            microseconds=struct.unpack("<Q", data[24:32])[0] / 10
                        )
                    ).isoformat(),
                )
            )
            tokens.append((binascii.hexlify(data[24:32])))
    if type == "5455":
        if data_len >= 5:
            ts_types = []
            flags = data[0]
            if flags & 0x01:
                ts_types.append("mtime")
            if flags & 0x02:
                ts_types.append("atime")
            if flags & 0x04:
                ts_types.append("ctime")

            tuples.append(('time_flags', ts_types))
            tokens.append(('{:x}'.format(data[0])))
            if len(ts_types) >= 1:
                tuples.append(
                    (
                        "time_" + ts_types[0],
                        datetime.datetime.utcfromtimestamp(
                            struct.unpack("<I", data[1:5])[0]
                        ).isoformat(),
                    )
                )
                tokens.append((binascii.hexlify(data[1:5])))
            if data_len >= 9 and len(ts_types) >= 2:
                tuples.append(
                    (
                        "time_" + ts_types[1],
                        datetime.datetime.utcfromtimestamp(
                            struct.unpack("<I", data[5:9])[0]
                        ).isoformat(),
                    )
                )
                tokens.append((binascii.hexlify(data[5:9])))
            if data_len >= 13 and len(ts_types) >= 3:
                tuples.append(
                    (
                        "time_" + ts_types[2],
                        datetime.datetime.utcfromtimestamp(
                            struct.unpack("<I", data[9:13])[0]
                        ).isoformat(),
                    )
                )
                tokens.append((binascii.hexlify(data[9:13])))
    if type == "7875":
        if data_len >= 6 and data[0] == 1:
            tuples.append(('unix_version', data[0]))
            tokens.append(('{:x}'.format(data[0])))
            tuples.append(('unix_uid_size', data[1]))
            tokens.append(('{:x}'.format(data[1])))
            if data[1] == 4:
                tuples.append(('unix_uid', struct.unpack("<I", data[2:6])[0]))
                tokens.append((binascii.hexlify(data[2:6])))
            tuples.append(('unix_guid_size', data[6]))
            tokens.append(('{:x}'.format(data[6])))
            if data_len >= 11 and data[6] == 4:
                tuples.append(('unix_gid', struct.unpack("<I", data[7:11])[0]))
                tokens.append((binascii.hexlify(data[7:11])))
    if type == "d935":
        if data_len >= 2:
            tuples.append(('andriod_alignment', data[0]))
            tokens.append(('{:x}'.format(data[0])))
            tuples.append(('andriod_padding_length', data_len))
            tokens.append((binascii.hexlify(data[1:])))
    if type == "a220":
        if data_len >= 4 and data[0:2] == b'\x28\xa0':
            tuples.append(("ms_pad_sig", binascii.hexlify(data[0:2])))
            tokens.append((binascii.hexlify(data[0:2])))
            tuples.append(('ms_pad_value', struct.unpack("<H", data[2:4])[0]))
            tokens.append((binascii.hexlify(data[2:4])))
            tuples.append(('ms_pad_length', data_len - 4))
            tokens.append((binascii.hexlify(data[4:])))
    if type == "9901":
        if data_len >= 7:
            tuples.append(("aes_version", struct.unpack("<H", data[0:2])[0]))
            tokens.append((binascii.hexlify(data[0:2])))
            tuples.append(("aes_vendor", data[2:4]))
            tokens.append((binascii.hexlify(data[2:4])))
            if data[4] == 0x01:
                tuples.append(("aes_strength", 128))
            elif data[4] == 0x02:
                tuples.append(("aes_strength", 192))
            elif data[4] == 0x03:
                tuples.append(("aes_strength", 256))
            else:
                tuples.append(("aes_strength", "unknown%i" % (data[4])))
            tokens.append(('{:x}'.format(data[4])))
            tuples.append(
                ("aes_method", label_method(struct.unpack("<H", data[5:7])[0]))
            )
            tokens.append((binascii.hexlify(data[5:7])))

    return tuples, tokens


def parse_extra_field(data):
    data_len = len(data)
    offset = 0
    fields = []
    field_types = []
    extra_tokens = []
    while offset <= (data_len - 4):
        field_type = "%04x" % struct.unpack("<H", data[offset : offset + 2])[0]
        field_len = struct.unpack("<H", data[offset + 2 : offset + 4])[0]
        field_data = data[offset + 4 : offset + 4 + field_len]

        extra_tokens.append(binascii.hexlify(data[offset : offset + 2]))
        extra_tokens.append(binascii.hexlify(data[offset + 2 : offset + 4]))

        if field_type in known_extra_types:
            field_types.append(known_extra_types[field_type])
            tuples, tokens = parse_extra_data(field_data, field_type)
            fields.extend(tuples)
            extra_tokens.extend(tokens)
        else:
            field_types.append(field_type)
            extra_tokens.append(binascii.hexlify(field_data))

        offset = offset + 4 + field_len
    unparsed_len = data_len - offset

    return field_types, fields, extra_tokens, unparsed_len


def parse_zip(f, decompress_files=False, derive_deflate_level=False):
    '''
    return a list of dictionaries for each file in archive, archive attributes
        decompress_files indicates that it is desired to decompress files, for example, to check size and CRC
        derive_deflate_level requires re-compressing the data upto 10 times, implies decompress_files

    '''

    if derive_deflate_level:
        decompress_files = True

    if decompress_files:

        decompressed_files = []
        decompress_errors = []
        decompressed_CRCs = []

    with zipfile.ZipFile(f, 'r') as z:
        entries = z.infolist()

        if decompress_files:
            for entry in entries:
                if entry.flag_bits & 0x0001:
                    # handle encrypted
                    decompressed_files.append("")
                    decompress_errors.append("")
                    decompressed_CRCs.append(0)
                else:
                    try:
                        decompressed_data = z.open(entry).read()
                        decompress_errors.append("")
                    except Exception as e:
                        decompressed_data = ""
                        decompress_errors.append(str(e))
                    decompressed_files.append(decompressed_data)
                    decompressed_CRCs.append(zlib.crc32(decompressed_data) & 0xFFFFFFFF)

    '''
    dir(z)
    ['NameToInfo', '_RealGetContents', '__class__', '__del__', '__delattr__', '__dict__', '__doc__', '__enter__', '__exit__', '__format__', '__getattribute__', '__hash__', '__init__', '__module__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '__weakref__', '_allowZip64', '_comment', '_didModify', '_extract_member', '_filePassed', '_writecheck', 'close', 'comment', 'compression', 'debug', 'extract', 'extractall', 'filelist', 'filename', 'fp', 'getinfo', 'infolist', 'mode', 'namelist', 'open', 'printdir', 'pwd', 'read', 'setpassword', 'start_dir', 'testzip', 'write', 'writestr']
    '''
    archive = {}
    archive["comment"] = z.comment
    archive["dir_offset"] = z.start_dir
    files = []
    '''
    dir(entry)
    ['CRC', 'FileHeader', '__class__', '__delattr__', '__doc__', '__format__', '__getattribute__', '__hash__', '__init__', '__module__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__slots__', '__str__', '__subclasshook__', '_decodeExtra', '_decodeFilename', '_encodeFilenameFlags', '_raw_time', 'comment', 'compress_size', 'compress_type', 'create_system', 'create_version', 'date_time', 'external_attr', 'extra', 'extract_version', 'file_size', 'filename', 'flag_bits', 'header_offset', 'internal_attr', 'orig_filename', 'reserved', 'volume']
    '''

    local_header_end = None
    cd_start = z.start_dir

    for entry in entries:
        file = {}
        file['create_ver'] = entry.create_version
        file['create_sys_raw'] = entry.create_system
        file['extract_ver'] = entry.extract_version
        file['flags_raw'] = entry.flag_bits
        file['method_raw'] = entry.compress_type
        file['date'] = "%04i-%02i-%02i" % (
            entry.date_time[0],
            entry.date_time[1],
            entry.date_time[2],
        )
        file['time'] = "%02i:%02i:%02i" % (
            entry.date_time[3],
            entry.date_time[4],
            entry.date_time[5],
        )
        file['crc_raw'] = entry.CRC
        file['crc'] = "%08x" % int((entry.CRC))
        file['c_size'] = entry.compress_size
        file['u_size'] = entry.file_size
        file['volume'] = entry.volume
        file['int_attr_raw'] = entry.internal_attr
        file['ext_attr_raw'] = entry.external_attr
        file['filename'] = entry.filename
        file['extra'] = binascii.hexlify(entry.extra)
        file['comment'] = entry.comment
        file['create_sys'] = label_create_software(file['create_sys_raw'])
        file['flags'] = label_flags(file['flags_raw'], file['method_raw'])
        file['flags_short'] = label_flags_short(file['flags'])
        file['method'] = label_method(file['method_raw'])
        file['int_attr'] = label_internal_attributes(file['int_attr_raw'])
        file['ext_attr_dos'] = label_external_attributes_dos(file['ext_attr_raw'])
        file['ext_attr_dos_short'] = label_external_attributes_dos_short(
            file['ext_attr_dos']
        )
        file['ext_attr_posix'] = label_external_attributes_posix(file['ext_attr_raw'])

        (
            file['extra_types'],
            file['extra_values'],
            file['extra_tokens'],
            file['extra_gap'],
        ) = parse_extra_field(entry.extra)

        # get offsets for central directory, have to parse again
        if cd_start:
            file['offset'] = cd_start
            f.seek(cd_start + 28)
            fname_len, extra_len, comment_len, disk_num = struct.unpack(
                "<HHHH", f.read(8)
            )
            file['disk_num'] = disk_num
            file['fname_len'] = fname_len
            file['extra_len'] = extra_len
            file['comment_len'] = comment_len
            f.seek(cd_start + 46 + fname_len + extra_len + comment_len)
            file['end'] = f.tell()
            magic = f.read(4)
            if magic == "PK\x01\x02":
                cd_start = f.tell() - 4
            else:
                cd_start = None

        file['l_offset'] = entry.header_offset
        f.seek(entry.header_offset)

        if local_header_end and local_header_end != file['l_offset']:
            file['l_gap'] = file['l_offset'] - local_header_end

        zip64 = False

        if decompress_files:
            file['decompress_size'] = len(decompressed_files[len(files)])
            file['decompress_crc'] = decompressed_CRCs[len(files)]
            file['decompress_errors'] = decompress_errors[len(files)]

        fheader = struct.unpack(
            zipfile.structFileHeader, f.read(zipfile.sizeFileHeader)
        )
        if fheader[zipfile._FH_SIGNATURE] == zipfile.stringFileHeader:
            file['l_extract_ver'] = fheader[zipfile._FH_EXTRACT_VERSION]
            file['l_flags_raw'] = fheader[zipfile._FH_GENERAL_PURPOSE_FLAG_BITS]
            file['l_method_raw'] = fheader[zipfile._FH_COMPRESSION_METHOD]
            t = fheader[zipfile._FH_LAST_MOD_TIME]
            d = fheader[zipfile._FH_LAST_MOD_DATE]
            file['l_date'] = "%04i-%02i-%02i" % (
                (d >> 9) + 1980,
                (d >> 5) & 0xF,
                d & 0x1F,
            )
            file['l_time'] = "%02i:%02i:%02i" % (
                t >> 11,
                (t >> 5) & 0x3F,
                (t & 0x1F) * 2,
            )
            file['l_crc'] = "%08x" % (fheader[zipfile._FH_CRC])
            file['l_c_size'] = fheader[zipfile._FH_COMPRESSED_SIZE]
            file['l_u_size'] = fheader[zipfile._FH_UNCOMPRESSED_SIZE]

            fname_len = fheader[zipfile._FH_FILENAME_LENGTH]
            extra_len = fheader[zipfile._FH_EXTRA_FIELD_LENGTH]
            file['l_extra_len'] = extra_len
            file['l_fname_len'] = fname_len

            if fname_len:
                if file['l_flags_raw'] & 0x800:
                    fname = f.read(fname_len).decode("utf-8", errors="replace")
                else:
                    fname = f.read(fname_len).decode("cp437", errors="replace")
            else:
                fname = ""
            if extra_len:
                extra = f.read(extra_len)
            else:
                extra = b''
            (
                file['l_extra_types'],
                file['l_extra_values'],
                file['l_extra_tokens'],
                file['l_extra_gap'],
            ) = parse_extra_field(extra)

            # does this need adjusted in event of zip64?
            compressed_data_size = file['c_size']

            file['l_data_offset'] = f.tell()

            compressed_data = f.read(compressed_data_size)

            if (
                derive_deflate_level
                and file['method_raw'] == 8
                and not (file['flags_raw'] & 0x0001)
            ):
                (
                    file['derived_deflate_level_max'],
                    file['derived_deflate_level_min'],
                    file['derived_deflate_size'],
                    file['derived_deflate_match'],
                ) = search_deflate_level(
                    compressed_data, decompressed_files[len(files)]
                )

            # descriptor
            if file['l_flags_raw'] & 0x0008:
                file['desc_offset'] = f.tell()

                data = f.read(4)
                # check for signature
                if data == "PK\x07\x08":
                    file['desc_sig'] = 1
                    data = f.read(4)
                else:
                    file['desc_sig'] = 0
                file['desc_crc'] = "%08x" % (struct.unpack("<L", data))
                if zip64:
                    spec = "<QQ"
                    slen = 16
                else:
                    spec = "<LL"
                    slen = 8
                file['desc_c_size'], file['desc_u_size'] = struct.unpack(
                    spec, f.read(slen)
                )
                file['desc_len'] = f.tell() - file['desc_offset']

            file['l_end'] = f.tell()
            local_header_end = file['l_end']

            file['l_filename'] = fname
            file['l_extra'] = binascii.hexlify(extra)

            file['l_flags'] = label_flags(file['l_flags_raw'], file['l_method_raw'])
            file['l_flags_short'] = label_flags_short(file['l_flags'])
            file['l_method'] = label_method(file['l_method_raw'])
            file['compress_flags'] = label_compress_flags(
                compressed_data, file['l_method_raw'], file['l_flags_raw']
            )
            file['compress_flags_short'] = label_compress_flags_short(
                file['compress_flags']
            )

            # compare the local and central directory headers
            deltas = []

            if file['extract_ver'] != file['l_extract_ver']:
                deltas.append("extract_ver")
            if file['flags_raw'] != file['l_flags_raw']:
                deltas.append("flags")
            if file['method_raw'] != file['l_method_raw']:
                deltas.append("method")
            if file['time'] != file['l_time']:
                deltas.append("time")
            if file['date'] != file['l_date']:
                deltas.append("date")
            if file['crc'] != file['l_crc']:
                deltas.append("crc")
            if file['c_size'] != file['l_c_size']:
                deltas.append("c_size")
            if file['u_size'] != file['l_u_size']:
                deltas.append("u_size")
            if file.get('fname_len', 0) != file['l_fname_len']:
                deltas.append("fname_len")
            if file.get('extra_len', 0) != file['l_extra_len']:
                deltas.append("extra_len")
            if file['filename'] != file['l_filename']:
                deltas.append("filename")
            if file['extra'] != file['l_extra']:
                deltas.append("extra")

            file['local_central_header_deltas'] = deltas

        files.append(file)

    archive['files'] = files
    archive['dir_end'] = files[0]['end']

    # parse the end of directory data
    f.seek(archive["dir_end"])
    magic = f.read(4)

    '''
      4.3.14  Zip64 end of central directory record

        zip64 end of central dir
        signature                       4 bytes  (0x06064b50)
        size of zip64 end of central
        directory record                8 bytes
        version made by                 2 bytes
        version needed to extract       2 bytes
        number of this disk             4 bytes
        number of the disk with the
        start of the central directory  4 bytes
        total number of entries in the
        central directory on this disk  8 bytes
        total number of entries in the
        central directory               8 bytes
        size of the central directory   8 bytes
        offset of start of central
        directory with respect to
        the starting disk number        8 bytes
        zip64 extensible data sector    (variable size)
    '''
    if magic == "PK\x06\x06":
        end_dir64 = {}
        end_dir64['end_dir64_offset'] = f.tell() - 4
        end_dir64_stuct = "<QBBHLLQQQQ"
        end_dir64_data = f.read(struct.calcsize(end_dir64_stuct))
        (
            end_dir64['end_dir64_size'],
            end_dir64['create_ver'],
            end_dir64['create_sys_raw'],
            end_dir64['extract_ver'],
            end_dir64['disk_num'],
            end_dir64['disk_num_dir'],
            end_dir64['num_entries_disk'],
            end_dir64['num_entries'],
            end_dir64['dir_size'],
            end_dir64['dir_offset'],
        ) = struct.unpack(end_dir64_stuct, end_dir64_data)
        end_dir64['create_sys'] = label_create_software(end_dir64['create_sys_raw'])
        if end_dir64['end_dir64_size'] > struct.calcsize(end_dir64_stuct):
            end_dir64['extended'] = binascii.hexlify(
                f.read(end_dir64['end_dir64_size'] - struct.calcsize(end_dir64_stuct))
            )
        end_dir64['end_dir64_end'] = f.tell()
        archive['end_dir64'] = end_dir64
        magic = f.read(4)

    '''
       4.3.15 Zip64 end of central directory locator

      zip64 end of central dir locator
      signature                       4 bytes  (0x07064b50)
      number of the disk with the
      start of the zip64 end of
      central directory               4 bytes
      relative offset of the zip64
      end of central directory record 8 bytes
      total number of disks           4 bytes
    '''

    if magic == "PK\x06\x07":
        loc_dir64 = {}
        loc_dir64['loc_dir64_offset'] = f.tell() - 4
        loc_dir64_stuct = "<LQL"
        loc_dir64_data = f.read(struct.calcsize(loc_dir64_stuct))
        (
            loc_dir64['disk_num_end_dir64'],
            loc_dir64['end_dir64_offset'],
            loc_dir64['num_disks'],
        ) = struct.unpack(loc_dir64_stuct, loc_dir64_data)
        loc_dir64['loc_dir64_end'] = f.tell()
        archive['loc_dir64'] = loc_dir64
        magic = f.read(4)

    '''
       4.3.16  End of central directory record:

      end of central dir signature    4 bytes  (0x06054b50)
      number of this disk             2 bytes
      number of the disk with the
      start of the central directory  2 bytes
      total number of entries in the
      central directory on this disk  2 bytes
      total number of entries in
      the central directory           2 bytes
      size of the central directory   4 bytes
      offset of start of central
      directory with respect to
      the starting disk number        4 bytes
      .ZIP file comment length        2 bytes
      .ZIP file comment       (variable size)
    '''
    if magic == "PK\x05\x06":
        end_directory = {}
        end_directory['end_dir_offset'] = f.tell() - 4
        end_directory_stuct = "<HHHHLLH"
        end_directory_data = f.read(struct.calcsize(end_directory_stuct))
        (
            end_directory['disk_num'],
            end_directory['disk_num_dir'],
            end_directory['num_entries_disk'],
            end_directory['num_entries'],
            end_directory['dir_size'],
            end_directory['dir_offset'],
            end_directory['comment_len'],
        ) = struct.unpack(end_directory_stuct, end_directory_data)
        if end_directory['comment_len']:
            end_directory['comment'] = f.read(end_directory['comment_len']).decode(
                "utf8", errors="replace"
            )
        end_directory['end_dir_end'] = f.tell()
        archive['end_dir'] = end_directory

    return archive


class Xyz(WorkerPlugin):
    def __init__(self, config: StoqConfigParser) -> None:
        super().__init__(config)
        self.decompress_files = config.getboolean(
            'options', 'decompress_files', fallback=True
        )
        self.derive_deflate_level = config.getboolean(
            'options', 'derive_deflate_level', fallback=True
        )

    async def scan(self, payload: Payload, request: Request) -> WorkerResponse:
        results = parse_zip(
            BytesIO(payload.content),
            decompress_files=self.decompress_files,
            derive_deflate_level=self.derive_deflate_level,
        )
        return WorkerResponse(results)
