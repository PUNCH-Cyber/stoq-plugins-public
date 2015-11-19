{% block title %}*TrID Results*{% endblock %}
{%block body %}

*md5:* {{ results["md5"] }}
*sha1:* {{ results["sha1"] }}
*sha256:* {{ results["sha256"] }}
*Results:*
{% for result in results["results"] %}
{% for hit in result["hits"] %}
    *{{ hit["likely"] }}* {{ hit["extension"] }} {{ hit["type"]}}
{% endfor %}
{% endfor %}
{% endblock %}
