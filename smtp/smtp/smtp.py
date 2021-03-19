#!/usr/bin/env python3

#   Copyright 2014-present PUNCH Cyber Analytics Group
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

from email import policy
from bs4 import UnicodeDammit  # type: ignore
from typing import List, Dict
from email.parser import Parser
from urllib.parse import unquote
from email.message import Message
from dateutil.parser import parse as dtparse

from stoq.plugins import WorkerPlugin
from stoq.helpers import StoqConfigParser
from stoq import Error, Payload, Request, WorkerResponse, ExtractedPayload, PayloadMeta


class SMTPPlugin(WorkerPlugin):
    def __init__(self, config: StoqConfigParser) -> None:
        super().__init__(config)

        ioc_keys: List[str] = [
            'received',
            'x-orig-ip',
            'x-originating-ip',
            'x-remote-ip',
            'x-sender-ip',
            'body',
            'body_html',
        ]
        self.omit_body = config.getboolean('options', 'omit_body', fallback=False)
        self.always_dispatch = config.getlist('options', 'always_dispatch', fallback=[])
        self.archive_attachments = config.getboolean(
            'options', 'archive_attachments', fallback=True
        )
        self.extract_iocs = config.getboolean('options', 'extract_iocs', fallback=False)
        self.ioc_keys = config.getlist('options', 'ioc_keys', fallback=ioc_keys)

    async def scan(self, payload: Payload, request: Request) -> WorkerResponse:
        message_json: Dict[str, str] = {}
        attachments: List[ExtractedPayload] = []
        errors: List[Error] = []
        ioc_content: str = ''
        session = UnicodeDammit(payload.content).unicode_markup
        message = Parser(policy=policy.default).parsestr(session)

        try:
            # Check for invalid date string
            # https://bugs.python.org/issue30681
            message.get('Date')
        except TypeError:
            date_header = [d[1] for d in message._headers if d[0] == 'Date'][0]
            date_header = dtparse(date_header).strftime('%c %z')
            message.replace_header('Date', date_header)

        # Create a dict of the SMTP headers
        for header, value in message.items():
            curr_header = header.lower()
            if curr_header in message_json:
                message_json[curr_header] += f'\n{value}'
            else:
                message_json[curr_header] = value

        if not self.omit_body:
            message_json['body'] = self._get_body(message, 'plain')
            message_json['body_html'] = self._get_body(message, 'html')

        if self.extract_iocs:
            for k in self.ioc_keys:
                if k in message_json:
                    ioc_content += f'\n{message_json[k]}'
                elif k == 'body' and k not in message_json:
                    b = self._get_body(message, 'plain')
                    if b:
                        ioc_content += b
                elif k == 'body_html' and k not in message_json:
                    b = self._get_body(message, 'html')
                    if b:
                        ioc_content += b

        for mailpart in message.iter_attachments():
            if mailpart.get_content_type() == 'message/rfc822':
                for part in mailpart.get_payload():
                    try:
                        attachment_meta = PayloadMeta(
                            should_archive=self.archive_attachments,
                            extra_data={
                                'charset': part.get_content_charset(),
                                'content-description': part.get('Content-Description'),
                                'disposition': part.get_content_disposition(),
                                'filename': part.get_filename(),
                                'type': part.get_content_type(),
                            },
                            dispatch_to=['smtp'],
                        )
                        attachment = ExtractedPayload(part.as_bytes(), attachment_meta)
                        attachments.append(attachment)
                    except Exception as err:
                        errors.append(
                            Error(
                                error=f'Failed rfc822 attachment: {err}',
                                plugin_name=self.plugin_name,
                                payload_id=payload.results.payload_id,
                            )
                        )
            else:
                try:
                    attachment_meta = PayloadMeta(
                        should_archive=self.archive_attachments,
                        extra_data={
                            'charset': mailpart.get_content_charset(),
                            'content-description': mailpart.get('Content-Description'),
                            'disposition': mailpart.get_content_disposition(),
                            'filename': mailpart.get_filename(),
                            'type': mailpart.get_content_type(),
                        },
                        dispatch_to=self.always_dispatch,
                    )
                    attachment = ExtractedPayload(
                        mailpart.get_content(), attachment_meta
                    )
                    attachments.append(attachment)
                except Exception as err:
                    errors.append(
                        Error(
                            error=f'Failed extracting attachment: {err}',
                            plugin_name=self.plugin_name,
                            payload_id=payload.results.payload_id,
                        )
                    )
        if self.extract_iocs:
            ioc_meta = PayloadMeta(should_archive=False, dispatch_to=['iocextract'])
            attachments.append(ExtractedPayload(ioc_content.encode(), ioc_meta))
        return WorkerResponse(message_json, errors=errors, extracted=attachments)

    def _get_body(self, message: Message, part: str) -> str:
        # Extract the e-mail body, to include HTML if available
        # We will use try and except because it is much faster than
        # validating if the objects exist.
        content = ''
        if part == 'plain':
            try:
                content = UnicodeDammit(
                    message.get_body(preferencelist=('plain')).get_payload(decode=True)
                ).unicode_markup
            except AttributeError:
                pass
        elif part == 'html':
            try:
                content = UnicodeDammit(
                    message.get_body(preferencelist=('html')).get_payload(decode=True)
                ).unicode_markup
            except AttributeError:
                pass
        if content:
            content = unquote(content)
        return content
