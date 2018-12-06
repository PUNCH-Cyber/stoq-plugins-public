rule valid_syntax_rule
{
    meta:
        plugin = "test_plugin"
        save = "True"
    strings:
        $a = "this too shall pass"
    condition:
        any of them
}

rule invalid_syntax
{
    meta:
        plugin = "text_plugin"
        save = "False"
    strings:
        $a = "this shall fail miserably"
    condition:
        any of them