{% block title %}*IOCExtract Results*{% endblock %}
{%block body %}

{% for result in results["results"] %}
{% if result["domain"]|length > 0 %}
*Domains:*
{% for domain in result["domain"] %}
{{ domain }}
{% endfor %}
{% endif %}

{% if result["ipv4"]|length > 0 %}
*IPv4 Addresses:*
{% for ip in result["ipv4"] %}
{{ ip }}
{% endfor %}
{% endif %}

{% if result["ipv6"]|length > 0 %}
*IPv6 Addresses:*
{% for ip in result["ipv6"] %}
{{ ip }}
{% endfor %}
{% endif %}

{% if result["md5"]|length > 0 %}
*MD5 Hashes:*
{% for hash in result["md5"] %}
{{ hash }}
{% endfor %}
{% endif %}

{% if result["sha1"]|length > 0 %}
*SHA1 Hashes:*
{% for hash in result["sha1"] %}
{{ hash }}
{% endfor %}
{% endif %}

{% if result["sha256"]|length > 0 %}
*SHA256 Hashes:*
{% for hash in result["sha256"] %}
{{ hash }}
{% endfor %}
{% endif %}

{% if result["sha512"]|length > 0 %}
*SHA512 Hashes:*
{% for hash in result["sha512"] %}
{{ hash }}
{% endfor %}
{% endif %}

{% if result["email"]|length > 0 %}
*E-Mail Addresses:*
{% for email in result["email"] %}
{{ email }}
{% endfor %}
{% endif %}

{% if result["mac_address"]|length > 0 %}
*MAC Addresses:*
{% for mac in result["mac_addresses"] %}
{{ mac }}
{% endfor %}
{% endif %}

{% if result["uri"]|length > 0 %}
*URIs:*
{% for uri in result["uri"] %}
{{ uri }}
{% endfor %}
{% endif %}

{% endfor %}
{% endblock %}

