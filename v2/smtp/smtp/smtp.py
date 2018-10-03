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

        if plugin_opts and 'omit_body' in plugin_opts:
            self.omit_body = plugin_opts['omit_body']
        elif config.has_option('options', 'omit_body'):
            self.omit_body = config.getboolean('options', 'omit_body')
        else:
            self.omit_body = False

        if plugin_opts and 'extract_iocs' in plugin_opts:
            self.extract_iocs = plugin_opts['extract_iocs']
        elif config.has_option('options', 'extract_iocs'):
            self.extract_iocs = config.getboolean('options', 'extract_iocs')
        else:
            self.extract_iocs = False

    def scan(
            self,
            payload: Payload,
            request_meta: RequestMeta,
    ) -> WorkerResponse:

        message_json = {}
        attachments = []
        errors = []
        ioc_content = ''
        email_session = UnicodeDammit(payload.content).unicode_markup
        message = pyzmail.message_from_string(email_session)

        # Create a dict of the SMTP headers
        for header in message.keys():
            curr_header = header.lower()
            if curr_header in message_json:
                # If the header key already exists, let's join them
                message_json[curr_header] += f'\n{message.get_decoded_header(header)}'
            else:
                message_json[curr_header] = message.get_decoded_header(header)

        if not self.omit_body:
            # Extract the e-mail body, to include HTML if available
            message_json['body'] = '' if message.text_part is None else UnicodeDammit(
                message.text_part.get_payload()).unicode_markup
            message_json['body_html'] = '' if message.html_part is None else UnicodeDammit(
                message.html_part.get_payload()).unicode_markup

        if self.extract_iocs:
            ioc_keys = [
                'src_ip',
                'dest_ip',
                'received',
                'x-orig-ip',
                'x-originating-ip',
                'x-remote-ip',
                'x-sender-ip',
                'body',
                'body_html'
                ]

            for k in ioc_keys:
                if k in message_json:
                    ioc_content += f'{message_json[k]}\n'

        # Handle attachments
        for mailpart in message.mailparts:
            # Skip if the attachment is a body part
            if mailpart.is_body:
                if self.extract_iocs:
                    ioc_content += UnicodeDammit(mailpart.get_payload()).unicode_markup
                continue
            try:
                attachment_meta = PayloadMeta(extra_data={
                    'charset': mailpart.charset,
                    'content-description': mailpart.part.get('Content-Description'),
                    'content-id': mailpart.content_id,
                    'disposition': mailpart.disposition,
                    'filename': mailpart.filename if mailpart.filename else mailpart.sanitized_filename,
                    'type': mailpart.type
                    })
                attachment = ExtractedPayload(mailpart.get_payload(), attachment_meta)
                attachments.append(attachment)
            except Exception as err:
                errors.append(f'Failed extracting attachment: {err}')

        if self.extract_iocs:
            ioc_meta = PayloadMeta(should_archive=False, dispatch_to=['iocextract'])
            attachments.append(ExtractedPayload(ioc_content.encode(), ioc_meta))

        return WorkerResponse(message_json, errors=errors, extracted=attachments)
