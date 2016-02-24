{% block title %}*IOCExtract Results*{% endblock %}
{%block body %}

{% for result in results["results"] %}
{% if result["domain"]|length > 0 %}
*Domains:*
{% for domain in result["scan"]["domain"] %}
{{ domain }}
{% endfor %}
{% endif %}

{% if result["scan"]["ipv4"]|length > 0 %}
*IPv4 Addresses:*
{% for ip in result["scan"]["ipv4"] %}
{{ ip }}
{% endfor %}
{% endif %}

{% if result["scan"]["ipv6"]|length > 0 %}
*IPv6 Addresses:*
{% for ip in result["scan"]["ipv6"] %}
{{ ip }}
{% endfor %}
{% endif %}

{% if result["scan"]["md5"]|length > 0 %}
*MD5 Hashes:*
{% for hash in result["scan"]["md5"] %}
{{ hash }}
{% endfor %}
{% endif %}

{% if result["scan"]["sha1"]|length > 0 %}
*SHA1 Hashes:*
{% for hash in result["scan"]["sha1"] %}
{{ hash }}
{% endfor %}
{% endif %}

{% if result["scan"]["sha256"]|length > 0 %}
*SHA256 Hashes:*
{% for hash in result["scan"]["sha256"] %}
{{ hash }}
{% endfor %}
{% endif %}

{% if result["scan"]["sha512"]|length > 0 %}
*SHA512 Hashes:*
{% for hash in result["scan"]["sha512"] %}
{{ hash }}
{% endfor %}
{% endif %}

{% if result["scan"]["email"]|length > 0 %}
*E-Mail Addresses:*
{% for email in result["scan"]["email"] %}
{{ email }}
{% endfor %}
{% endif %}

{% if result["scan"]["mac_address"]|length > 0 %}
*MAC Addresses:*
{% for mac in result["scan"]["mac_addresses"] %}
{{ mac }}
{% endfor %}
{% endif %}

{% if result["scan"]["uri"]|length > 0 %}
*URIs:*
{% for uri in result["scan"]["uri"] %}
{{ uri }}
{% endfor %}
{% endif %}

{% endfor %}
{% endblock %}

