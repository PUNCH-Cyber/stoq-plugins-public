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
        plugin = "xor"
        save = "True"
        xor_pt_this_prog = "This program"
        // xorkey = "This metadata is created by yarascan.py"
    strings:
        $this_prog = "This program" xor(0x01-0xFF)
    condition:
        any of them
}

rule test_xor_info_creation
{
    meta:
        plugin = "xor"
        save = "True"
        xor_pt_this_prog = "This program"
        xor_pt_this_prog_2b = "This program"
        // xor_info = "This metadata is created by yarascan.py, if plugin config xor_first_match is False"
    strings:
        $this_prog = "This program" xor(0x01-0xFF)
        $this_prog_2b = "Tiir qrngsal" xor(0x01-0xFF)
    condition:
        any of them
}
