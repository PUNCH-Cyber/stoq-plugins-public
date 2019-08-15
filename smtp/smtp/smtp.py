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

from email import policy
from bs4 import UnicodeDammit  # type: ignore
from email.parser import Parser
from urllib.parse import unquote
from email.message import Message
from configparser import ConfigParser
from typing import List, Dict, Optional

from stoq.plugins import WorkerPlugin
from stoq import Payload, RequestMeta, WorkerResponse, ExtractedPayload, PayloadMeta


class SMTPPlugin(WorkerPlugin):
    def __init__(self, config: ConfigParser, plugin_opts: Optional[Dict]) -> None:
        super().__init__(config, plugin_opts)

        self.omit_body: bool = False
        self.always_dispatch: List[str] = []
        self.archive_attachments: bool = True
        self.extract_iocs: bool = False
        self.ioc_keys: List[str] = [
            'received',
            'x-orig-ip',
            'x-originating-ip',
            'x-remote-ip',
            'x-sender-ip',
            'body',
            'body_html',
        ]

        if plugin_opts and 'omit_body' in plugin_opts:
            self.omit_body = plugin_opts['omit_body']
        elif config.has_option('options', 'omit_body'):
            self.omit_body = config.getboolean('options', 'omit_body')

        if plugin_opts and 'always_dispatch' in plugin_opts:
            if isinstance(plugin_opts['always_dispatch'], str):
                self.always_dispatch = [
                    x.strip() for x in plugin_opts['always_dispatch'].split(',')
                ]
            else:
                self.always_dispatch = plugin_opts['always_dispatch']
        elif config.has_option('options', 'always_dispatch'):
            self.always_dispatch = [
                x.strip() for x in config.get('options', 'always_dispatch').split(',')
            ]

        if plugin_opts and 'archive_attachments' in plugin_opts:
            self.archive_attachments = plugin_opts['archive_attachments']
        elif config.has_option('options', 'archive_attachments'):
            self.archive_attachments = config.getboolean(
                'options', 'archive_attachments'
            )

        if plugin_opts and 'extract_iocs' in plugin_opts:
            self.extract_iocs = plugin_opts['extract_iocs']
        elif config.has_option('options', 'extract_iocs'):
            self.extract_iocs = config.getboolean('options', 'extract_iocs')

        if plugin_opts and 'ioc_keys' in plugin_opts:
            if isinstance(plugin_opts['ioc_keys'], str):
                self.ioc_keys = [x.strip() for x in plugin_opts['ioc_keys'].split(',')]
            else:
                self.ioc_keys = plugin_opts['ioc_keys']
        elif config.has_option('options', 'ioc_keys'):
            self.ioc_keys = [
                x.strip() for x in config.get('options', 'ioc_keys').split(',')
            ]

    def scan(self, payload: Payload, request_meta: RequestMeta) -> WorkerResponse:
        message_json: Dict[str, str] = {}
        attachments: List[ExtractedPayload] = []
        errors: List[str] = []
        ioc_content: str = ''
        session = UnicodeDammit(payload.content).unicode_markup
        message = Parser(policy=policy.default).parsestr(session)

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
                        errors.append(f'Failed rfc822 attachment: {err}')
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
                    errors.append(f'Failed extracting attachment: {err}')
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
        return unquote(content)
