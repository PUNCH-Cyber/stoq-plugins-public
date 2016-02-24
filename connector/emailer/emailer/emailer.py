#   Copyright 2014-2015 PUNCH Cyber Analytics Group
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

Send results to recipients via e-mail

"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from stoq.plugins import StoqConnectorPlugin


class EmailConnector(StoqConnectorPlugin):

    def __init__(self):
        super().__init__()

    def activate(self, stoq):
        self.stoq = stoq
        super().activate()

    def save(self, payload, archive=False, **kwargs):
        """
        Send plugin results via e-mail

        :param str payload: Content to be saved
        :param bool archive: Unsupported
        :param **kwargs sender: Sender e-mail address to use
        :param **kwargs recipients: Comma (,) seperated list of recipients

        """

        if 'sender' in kwargs:
            sender = kwargs['sender']
        else:
            sender = self.sender

        if 'recipients' in kwargs:
            recipients = kwargs['recipients']
            if type(recipients) is not list:
                recipients = recipients.split(",")
        else:
            recipients = self.recipients_list

        if not recipients:
            self.stoq.log.error("No recipient defined!")
            return None

        msg = MIMEMultipart('alternative')
        msg['From'] = sender
        msg['To'] = ",".join(recipients)
        msg['Subject'] = "[stoQ] {} result".format(self.parentname)

        if type(payload) is dict:
            body = self.stoq.dumps(payload, compactly=False)
        else:
            body = payload

        text_part = MIMEText(body, 'plain')

        msg.attach(text_part)

        msg = msg.as_string()

        smtp_server = smtplib.SMTP(self.server)
        smtp_server.starttls()
        smtp_server.login(self.username, self.password)
        smtp_server.sendmail(sender, recipients, msg)
        smtp_server.quit()

        return True
