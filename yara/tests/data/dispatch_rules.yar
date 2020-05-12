rule test_dispatch_rule: tag1 tag2
{
    meta:
        plugin = "test_dispatch_plugin"
        save = "True"
    strings:
        $a = "testtesttest"
    condition:
        any of them
}

rule test_save_false
{
    meta:
        plugin = "save_false"
        save = "False"
    strings:
        $a = "save_false"
    condition:
        any of them
}

rule test_xorkey_creation
{
    meta:
        plugin = "xordecode"
        save = "True"
        xor_plaintext_for_string_this_prog = "This program"
        // xorkey = "Only extract first XOR key as str by yarascan.py, if xor_first_match is True"
        // xor_info = "Extract XOR keys as a list of tuples by yarascan.py, if xor_first_match is False"
    strings:
        $this_prog = "This program" xor(0x01-0xFF)
    condition:
        any of them
}

rule test_xor_info_creation
{
    meta:
        plugin = "xordecode"
        save = "True"
        xor_plaintext_for_string_this_prog = "This program"
        xor_plaintext_for_string_this_prog_2b = "This program"
        // xorkey = "Only extract first XOR key as str by yarascan.py, if xor_first_match is True"
        // xor_info = "Extract XOR keys as a list of tuples by yarascan.py, if xor_first_match is False"
    strings:
        $this_prog = "This program" xor(0x01-0xFF)
        $this_prog_2b = "Tiir qrngsal" xor(0x01-0xFF)
    condition:
        any of them
}
