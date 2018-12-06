rule test_scan_rule
{
    meta:
        plugin = "test_scan_plugin"
        save = "True"
    strings:
        $a = "testtesttest"
    condition:
        any of them
}

rule test_scan_metadata
{
    meta:
        plugin = "save_false"
        author = "Peter Rabbit"
    strings:
        $a = "scan_meta"
    condition:
        any of them
}

rule test_scan_metadata_bytes
{
    meta:
        plugin = "save_false"
        author = "Peter Rabbit"
        bytes = "\x41Neato"
    strings:
        $a = "meta_bytes"
    condition:
        any of them
}