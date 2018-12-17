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

Decorate results using a template

"""

import os
from pathlib import Path
from typing import Dict, Optional
from configparser import ConfigParser
from inspect import currentframe, getframeinfo
from jinja2.exceptions import TemplateNotFound
from jinja2 import Environment, FileSystemLoader, select_autoescape

from stoq.exceptions import StoqPluginException
from stoq.plugins import DecoratorPlugin, ConnectorPlugin
from stoq.data_classes import StoqResponse, DecoratorResponse


class JinjaPlugin(ConnectorPlugin, DecoratorPlugin):
    def __init__(self, config: ConfigParser, plugin_opts: Optional[Dict]) -> None:
        super().__init__(config, plugin_opts)

        self.template = None

        filename = getframeinfo(currentframe()).filename
        parent = Path(filename).resolve().parent

        if plugin_opts and 'template' in plugin_opts:
            self.template = plugin_opts['template']
        elif config.has_option('options', 'template'):
            self.template = config.get('options', 'template')
        if self.template:
            self.template = os.path.abspath(os.path.join(parent, self.template))

    def save(self, response: StoqResponse) -> None:
        """
        Print results to STDOUT

        """
        if 'jinja' in response.decorators:
            print(response.decorators['jinja'])
        else:
            print(response)

    def decorate(self, response: StoqResponse) -> DecoratorResponse:
        """
        Decorate results using a template

        """
        results = None
        try:
            dirname = os.path.dirname(self.template)
            basename = os.path.basename(self.template)
            env = Environment(
                loader=FileSystemLoader(dirname),
                trim_blocks=True,
                lstrip_blocks=True,
                autoescape=select_autoescape(default_for_string=True, default=True),
            )
            results = env.get_template(basename).render(response=response)
        except TemplateNotFound:
            raise StoqPluginException(f'Template path not found: {self.template}')

        return DecoratorResponse(results)
