/*
   Copyright 2014-2018 PUNCH Cyber Analytics Group

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

rule swf_file
{
    meta:
        plugin = "swfcarve"
        save = "True"
    strings:
        $cws = "CWS"
        $fws = "FWS"
        $zws = "ZWS"
    condition:
        any of them
}

rule xdp_file
{
    meta:
        plugin = "xdpcarve"
        save = "True"
    strings:
        $xdp = "xdp:xdp"
        $pdf = "<pdf "
    condition:
        all of them
}

rule ole_file
{
    meta:
        plugin = "ole"
        save = "False"
    strings:
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }
    condition:
        $ole at 0
}

rule ole_package_stream
{
    meta:
        plugin = "olepackagestream"
        save = "True"
    strings:
        $ole = { 02 00 }
    condition:
        $ole at 4
}

rule ole_with_vba
{
    meta:
        plugin = "mraptor"
        save = "True"
    strings:
        $zip = "PK"
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }
        // Attribute VB
        $vbastr1 = { 41 74 74 72 69 62 75 74 00 65 20 56 42 }
        $vbastr2 = "_VBA_PROJECT_CUR" wide
        $vbastr3 = "VBAProject"
        $vbaxml1 = "vbaData.xml"
        $vbaxml2 = "vbaProject.bin"
    condition:
        ($zip at 0 and any of ($vbaxml*)) or ($ole at 0 and any of ($vbastr*))
}

rule rtf_file
{
    meta:
        plugin = "rtf"
        save = "True"
    strings:
        $rtf = "{\\rt" nocase
    condition:
        $rtf at 0
}

rule exe_file
{
    meta:
        plugin = "pecarve"
        save = "True"
    strings:
        $MZ = "MZ"
        $ZM = "ZM"
        $dos_stub = "This program cannot be run in DOS mode"
        $win32_stub = "This program must be run under Win32"
    condition:
        ($MZ or $ZM) and ($dos_stub or $win32_stub)
}

rule zip_file
{
    meta:
        plugin = "decompress"
        save = "True"
    strings:
        $zip1 = { 50 4b 05 06 }
        $zip2 = { 50 4b 03 04 }
        $zip3 = { 50 4b 07 08 }
    condition:
        ($zip1 at 0) or ($zip2 at 0) or ($zip3 at 0)
}

rule ace_file
{
    meta:
        plugin = "decompress"
        save = "True"
    strings:
        // **ACE**
        $magic = { 2a 2a 41 43 45 2a 2a }
    condition:
        $magic at 7
}

rule xor_This_program
{
    meta:
        plugin = "xor"
        save = "True"
        xor_pt_this_prog = "This program"
        // xorkey = "Only extract first XOR key as str by yarascan.py, if xor_first_match is True"
        // xor_info = "Extract XOR keys as repr of list of tuples by yarascan.py, if xor_first_match is False"
    strings:
        $this_prog = "This program" xor(0x01-0xFF)
    condition:
        any of them
}
