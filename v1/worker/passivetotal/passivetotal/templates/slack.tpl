{% block title %}*PassiveTotal Results*{% endblock %}
{%block body %}

{% for result in results.results %}
*Query:* {{ result.raw_query }}
{% if result.results.records|length > 0 %}
*First Seen:* {{ result.results.first_seen }}
*Last Seen:* {{ result.results.last_seen }}
*Resolutions:*
    {% for resolution in result.results.records %}
        {% set resolve = resolution.resolve %}
        {% set first_seen = resolution.first_seen %}
        {% set last_seen = resolution.last_seen %}
        {% set sources = resolution.source %}
        {% set network = result.results.enrichment_map.get(resolve).network %}
        {% set asn = result.results.enrichment_map.get(resolve).asn %}
        {% set as_name = result.results.enrichment_map.get(resolve).as_name %}
        {% set isp = result.results.enrichment_map.get(resolve).isp %}
        {% set sinkhole = result.results.enrichment_map.get(resolve).sinkhole %}
        {% set country = result.results.enrichment_map.get(resolve).country %}
        ----------------------------------------
        *Resolution:* {{ resolve }}
        {% if network|length > 0 %}
        *Network:* {{ network }}
        {% endif %}
        *Sinkhole:* {{ sinkhole|string() }}
        {% if asn|length > 0 %}
        *ASN:* {{ asn }}
        {% endif %}
        {% if as_name|length > 0 %}
        *AS Name:* {{ as_name }}
        {% endif %}
        {% if country|length > 0 %}
        *Country:* {{ country }}
        {% endif %}
        {% if first_seen|length > 0 %}
        *First Seen:* {{ first_seen }}
        {% endif %}
        {% if last_seen|length > 0 %}
        *Last Seen:* {{ last_seen }}
        {% endif %}
    {% endfor %}
{% else %}
    No resolutions available
{% endif %}
{% endfor %}
{% endblock %}
