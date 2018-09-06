{% block title %}*PEInfo Results*{% endblock %}
{%block body %}

*md5:* {{ results["md5"] }}
*sha1:* {{ results["sha1"] }}
*sha256:* {{ results["sha256"] }}
*sha512:* {{ results["sha512"] }}
{% for result in results["results"] %}
*imphash:* {{ result["imphash"] }}
*compile time:* {{ result["compile_time"] }}
*is_packed:* {{ result["is_packed"] }}
{% if result['is_packed'] == True %}
*packer:* {{ result["packer"] }}
{% endif %}
*is_exe:* {{ result["is_exe"] }}
*is_dll:* {{ result["is_dll"] }}
*is_driver:* {{ result["is_driver"] }}
*is_valid:* {{ result["is_valid"] }}
*is_suspicious:* {{ result["is_suspicious"] }}
*machine_type:* {{ result["machine_type"] }}
*entypoint:* {{ result["entrypoint"] }}
*import_count:* {{ result["imports"]|length }}
*section_count:* {{ result["section_count"] }}
*section_names:*
{% for section in result["sections"] %}
   {{ section["name"] }}
{% endfor %}
{% endfor %}
{% endblock %}
