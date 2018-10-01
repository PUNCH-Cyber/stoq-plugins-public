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

Parse SMTP sessions

"""

from configparser import ConfigParser
from typing import Dict, Optional
import pyzmail
from bs4 import UnicodeDammit

from stoq import (
    Payload, RequestMeta, WorkerResponse,
    DispatcherResponse, ExtractedPayload, PayloadMeta)
from stoq.plugins import WorkerPlugin


class SMTPPlugin(WorkerPlugin):

    def __init__(self, config: ConfigParser,
                 plugin_opts: Optional[Dict]) -> None:
        super().__init__(config, plugin_opts)

        if plugin_opts and "omit_body" in plugin_opts:
            self.omit_body = plugin_opts["omit_body"]
        elif config.has_option("options", "omit_body"):
            self.omit_body = config.getboolean("options", "omit_body")
        else:
            self.omit_body = False

    def scan(
            self,
            payload: Payload,
            request_meta: RequestMeta,
    ) -> WorkerResponse:

        if not payload:
            self.log.warn("SMTP session is empty. Do you have permission to the source?")
            return False

        email_session = UnicodeDammit(payload.content).unicode_markup
        message_json = {}
        attachments = []
        errors = []
        message = pyzmail.message_from_string(email_session)

        # Create a dict of the headers in the session
        for k, _ in list(message.items()):
            curr_header = k.lower()
            if curr_header in message_json:
                # If the header key already exists, let's join them
                message_json[curr_header] += f"\n{message.get_decoded_header(k)}"
            else:
                message_json[curr_header] = message.get_decoded_header(k)

        # Extract the e-mail body, to include HTML if available
        message_json['body'] = '' if message.text_part is None else UnicodeDammit(
            message.text_part.get_payload()).unicode_markup
        message_json['body_html'] = '' if message.html_part is None else UnicodeDammit(
            message.html_part.get_payload()).unicode_markup

        # Make this easy, merge both text and html body within e-mail
        # for the purpose of extracting any IOCs
        # email_body = f"{message_json['body']}{message_json['body_html']}"

        # Handle attachments
        for mailpart in message.mailparts:
            try:
                filename = mailpart.filename
            except TypeError:
                filename = "None"

            if mailpart.type == "text/plain":
                try:
                    message_json['body'] += UnicodeDammit(mailpart.get_payload()).unicode_markup
                    continue
                except Exception as err:
                    errors.append(f'Failed parsing text/plain from attachment: {err}')

            try:
                attachment_meta = PayloadMeta(extra_data={
                    'filename': filename,
                    'content-description': mailpart.part.get('Content-Description'),
                    'type': mailpart.type
                    })
                attachment = ExtractedPayload(mailpart.get_payload(), attachment_meta)
                attachments.extend(attachment)
            except Exception as err:
                errors.append(f'Failed extracting TNEF object: {err}')

        # Make sure we delete the body and body_html keys if they are to
        # be omitted
        if self.omit_body:
            message_json.pop('body', None)
            message_json.pop('body_html', None)

        return WorkerResponse(message_json, errors=errors, extracted=attachments)
