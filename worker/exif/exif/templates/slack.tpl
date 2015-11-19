{% block title %}*EXIF Results*{% endblock %}
{%block body %}

*md5:* {{ results["md5"] }}
*sha1:* {{ results["sha1"] }}
*sha256:* {{ results["sha256"] }}
*sha512:* {{ results["sha512"] }}
{% for result in results["results"] %}
{% for k, v in result.items() %}
*{{ k }}:* {{ v }}
{% endfor %}
{% endfor %}
{% endblock %}
