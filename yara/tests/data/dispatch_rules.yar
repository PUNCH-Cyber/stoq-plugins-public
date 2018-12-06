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
