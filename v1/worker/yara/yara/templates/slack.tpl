{% block title %}*Yara Results*{% endblock %}
{%block body %}

*md5:* {{ results["md5"] }}
*sha1:* {{ results["sha1"] }}
*sha256:* {{ results["sha256"] }}
*sha512:* {{ results["sha512"] }}
{% for result in results["results"] %}
*hits:* {{ result["hits"]|length }}
{% for hit in result["hits"] %}
*Rule:* {{ hit["rule"] }}
{% endfor %}
{% endfor %}
{% endblock %}
