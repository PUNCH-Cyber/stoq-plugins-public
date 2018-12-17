stoQ Scan Results
-----------------

ScanID: {{ response['scan_id'] }}
Date: {{ response['time'] }}
Request Metadata:
  - Archive Payload: {{ response['request_meta']['archive_payloads'] }}
{% for k, v in response['request_meta']['extra_data'] %}
  - {{ k }}: {{ v }}
Total Payloads: {{ response['results']|length }}
{% endfor %}
Errors:
{% for error in response['errors'] %}
  - {{ error }}
{% endfor %}

Payloads:
{% for payload in response['results'] %}

--------------------------------------------------
  Payload ID: {{ payload['payload_id'] }}
  Size: {{ payload['size'] }}
  Extracted From: {{ payload['extracted_from'] }}
  Extracted By: {{ payload['extracted_by'] }}
  Metadata:
    - Archive Payload: {{ payload['payload_meta']['archive_payloads'] }}
    - Dispatch To: {{ payload['payload_meta']['dispatch_to']['archive_payloads'] }}
    {% for k, v in payload['payload_meta']['extra_data'].items() %}
    - {{ k }}: {{ v|safe }}
    {% endfor %}
  Archivers:
  {% for archiver in payload['archivers'] %}
    - {{ archiver }}
  {% endfor %}
  Worker Results:
  {% for worker in payload['workers'] %}
  {% for k, v in worker.items() %}
    {{ k }}:
      - {{ v|safe  }}
  {% endfor %}
  {% endfor %}
{% endfor %}