#!/usr/bin/env python3

#   Copyright 2014-2018 PUNCH Cyber Analytics Group
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
"""
Overview
========

Scan payloads using ACCE

"""
import locale
import re
import zipfile
from io import BytesIO
from json import JSONDecodeError
from time import sleep
from typing import Dict, List, Optional, Tuple

import requests
from requests.models import Response
from stoq import Error, ExtractedPayload, Payload, PayloadMeta, Request, WorkerResponse
from stoq.exceptions import StoqPluginException
from stoq.helpers import StoqConfigParser, get_md5
from stoq.plugins import WorkerPlugin


class AccePlugin(WorkerPlugin):
    def __init__(self, config: StoqConfigParser) -> None:
        super().__init__(config)

        self.acce_root_url = config.get(
            "options",
            "acce_root_url",
            fallback="https://free.acce.ciphertechsolutions.com/",
        )

        self.api_key = config.get("options", "api_key", fallback=None)
        if not self.api_key:
            raise StoqPluginException("ACCE API Key was not provided")
        self.auth_header = {"Authorization": f"Token " + self.api_key}
        self.delay = config.getint("options", "delay", fallback=10)
        self.max_attempts = config.getint(
            "options", "max_attempts", fallback=(60 * 5) / self.delay
        )
        self.wait_for_results = config.getboolean(
            "options", "wait_for_results", fallback=True
        )
        self.get_artifacts = config.getboolean(
            "options", "get_artifacts", fallback=True
        )
        self.should_archive_extracted = config.getboolean(
            "options", "should_archive_extracted", fallback=True
        )
        self.dispatch_extracted_to = config.getlist(
            "options", "dispatch_extracted_to", fallback=[]
        )
        self.windows_safe_encoding = config.getboolean(
            "options", "windows_safe_encoding", fallback=True
        )
        self.use_mwcp_legacy = config.getboolean(
            "options", "use_mwcp_legacy", fallback=False
        )

    async def scan(
        self, payload: Payload, request: Request
    ) -> Optional[WorkerResponse]:
        """
        Scan payloads using ACCE
        """

        errors: List[Error] = []
        artifacts: List[ExtractedPayload] = []
        submission_url = f"{self.acce_root_url}/api/v1/submissions"
        filename = payload.results.payload_meta.extra_data.get(
            "filename", get_md5(payload.content)
        )
        if isinstance(filename, bytes):
            filename = filename.decode()
        files = {"sample": (filename, payload.content)}
        response: Response = requests.post(
            submission_url, data={}, files=files, headers=self.auth_header
        )
        if response.status_code != 201:
            response_body = self._safe_get_json(response)
            if response_body.get("error", None):
                errors.append(response_body["error"])
            return WorkerResponse(response_body, errors=errors)
        results = self._safe_get_json(response)
        if results.get("error", None):
            errors.append(results["error"])
        if self.wait_for_results:
            results_url = results.get("result")
            if not results_url:
                errors.append(
                    "Results url not returned from original request, unable to retrieve results"
                )
            else:
                results, poll_errors = self._poll_for_results(results_url)
                if (
                    self.windows_safe_encoding
                    and locale.getpreferredencoding() == "cp1252"
                ):
                    results = self._escape_dict(results)
                    errors.append(
                        "Warning: to ensure compatability with other plugins results have been force encoded to cp1252 for compatability with Windows systems.  This can results in escaped unicode for characters not supporeted by Windows, such as other langauges.  You can disable this by setting windows_safe_encoding to False, but that may cause issues for other plugins on Windows systems."
                    )
                errors.extend(poll_errors)
                if self.get_artifacts:
                    artifacts, artifact_errors = self._get_submission_artifacts(
                        results_url
                    )
                    if artifact_errors:
                        errors.extend(artifact_errors)
        else:
            results[
                "message"
            ] = f"Sample {results.get('md5',default='file')} has been submitted to acce, but since wait_for_results is false this result does not contain the full results"
        return WorkerResponse(results, errors=errors, extracted=artifacts)

    def _safe_get_json(self, req: requests.Response, **kwargs) -> Dict:
        """
        Safely get a request JSON response

        Returns a dict with an error message if decoding fails
        """
        try:
            return req.json(**kwargs)
        except JSONDecodeError as e:
            return {"error": [e]}

    def _poll_for_results(self, url: str) -> Tuple[Dict, List[str]]:
        """
        Polls ACCE submission , waiting for results to finish processing
        Stops polling if:
            1) max_attempts is reached
            2) ACCE returns a non 200 status code
            3) ACCE returns an error in response body
        Returns dict of results and list of errors
        """
        errors = []
        for _ in range(self.max_attempts):
            result_req: Response = requests.get(
                url, headers=self.auth_header, params={"legacy": self.use_mwcp_legacy}
            )
            result_data = self._safe_get_json(result_req)

            if result_data.get("status") in ("running", "pending"):
                pass
            elif result_req.status_code != 200 or "error" in result_data:
                if "error" in result_data:
                    errors.append(result_data["error"])
                if result_req.status_code != 200:
                    errors.append(
                        f"Bad status code {result_req.status_code} from results polling"
                    )
                return result_data, errors
            elif "result" in result_data:
                return result_data.get("result"), errors

            sleep(self.delay)
        errors.append(
            f"Max poll attempts ({self.max_attempts}) exceeded after waiting {self.max_attempts * self.delay} seconds"
        )
        return result_data, errors

    def _get_submission_artifacts(
        self, url: str
    ) -> Tuple[List[ExtractedPayload], List[str]]:
        """
        Downloads artifacts produced by ACCE processing
        Extracts artifacts from artifact zip
        Returns a list of artifacts as stoq.ExtractedPayload and a list of errors
        """
        extracted = []
        errors = []
        from requests.models import Response

        response: Response = requests.get(url + "/archive", headers=self.auth_header)
        content = BytesIO(response.content)
        if not zipfile.is_zipfile(content):
            errors.append(
                "Expected content to be a zipfile, but zipfile.is_zipfile() returned False"
            )
        else:
            zip = zipfile.ZipFile(content)
            artifact_names = [
                x for x in zip.namelist() if re.search("^extracted_components/.+$", x)
            ]
            for artifact_name in artifact_names:
                extra_data = {"filename": artifact_name, "source": "ACCE"}
                payload_meta = PayloadMeta(
                    should_archive=self.should_archive_extracted,
                    extra_data=extra_data,
                    dispatch_to=self.dispatch_extracted_to,
                    should_scan=False,
                )
                payload = ExtractedPayload(
                    zip.read(artifact_name, pwd=b"infected"), payload_meta
                )
                extracted.append(payload)
        return extracted, errors

    # _escape_dict and escape_list are used to 'safely' convert strings with non cp1252 characters
    # Which can cause problems in other plugins on Windows systems
    # These can be removed if filedir.save updates to open files with a utf-8 encoding or in binary mode
    def _escape_dict(self, data: Dict) -> Dict:
        for key, value in list(data.items()):
            if isinstance(value, str):
                data[key] = value.encode(
                    locale.getpreferredencoding(), errors="backslashreplace"
                )
            elif isinstance(value, Dict):
                data[key] = self._escape_dict(value)
            elif isinstance(value, List):
                data[key] = self._escape_list(value)
        return data

    def _escape_list(self, data: List) -> List:
        for value in data:
            if isinstance(value, str):
                value = re.escape(value)
            elif isinstance(value, Dict):
                value = self._escape_dict(value)
            elif isinstance(value, List):
                value = self._escape_list(value)
        return data
