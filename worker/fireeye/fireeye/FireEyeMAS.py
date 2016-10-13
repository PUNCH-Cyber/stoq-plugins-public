#!/usr/bin/env python3

#######################
#
# FireEye API
#
# Copyright (c) 2015 United States Government/National Institutes of Health
# Author: Aaron Gee-Clough
# Modifications from original made by: Adam Trask, Marcus LaFerrera
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#
#####################

import re
import json
import demjson
import requests
import lxml.etree


class ApiVersion110(object):

    valid_durations = ('1_hour', '2_hours', '6_hours',
                       '12_hours', '24_hours', '48_hours')

    valid_info_levels = ('concise', 'normal', 'extended')

    valid_report_durations = ('pastWeek', 'pastMonth',
                              'pastThreeMonths', 'rangeReport')

    valid_profiles = ('winxp-sp2', 'winxp-sp3', 'win7-sp1', 'win7x64-sp1')

    valid_content_types = ('application/json', 'application/xml')

    def __init__(self, ax_address, verifySSL=True, apiToken=None,
                 clientToken=None, contentType='application/json'):
        self.base_url = 'https://{}/wsapis/v1.1.0'.format(ax_address)
        self.verify_SSL = verifySSL
        self.content_type = contentType
        self.api_token = apiToken
        self.client_token = clientToken

    def authenticate(self, username, password):

        headers = {}
        url = '{}/auth/login?'.format(self.base_url)

        if self.client_token:
            headers['X-FeClient-Token'] = self.client_token

        response = requests.post(url, auth=(username, password),
                                 headers=headers, verify=self.verify_SSL)

        if response.status_code == 200:
            self.api_token = response.headers['X-FeApi-Token']
        elif response.status_code == 400:
            raise Exception('Authentication Refused')
        elif response.status_code == 503:
            raise Exception('Web Services API server disabled')
        else:
            raise Exception('Unexpected response: {}'.format(response.text))

        return response

    def retrieve_alert(self, **kwargs):

        # Valid filters to be passed in kwargs
        valid_filter_params = ('alert_id',
                               'duration',
                               'info_level',
                               'file_name',
                               'file_type',
                               'url',
                               'md5',
                               'malware_name',
                               'malware_type',
                               'start_time',
                               'end_time')

        headers = {'X-FeApi-Token': self.api_token,
                   'Accept': self.content_type}

        url = '{}/alerts?'.format(self.base_url)

        for key, value in kwargs.items():
            if key in valid_filter_params:
                url = '{}&{}="{}"'.format(url, key, value)

        if self.client_token:
            headers['X-FeClient-Token'] = self.client_token

        response = requests.get(url, headers=headers, verify=self.verify_SSL)

        if response.status_code == 200:
            pass
        elif response.status_code == 400:
            raise Exception('Filter value invalid')
        else:
            raise Exception('Unexpected response: {}'.format(response.text))

        return response

    def retrieve_report_by_reportID(self, reportID, formatPDF=False,
                                    reportType='alertDetailsReport'):

        headers = {'X-FeApi-Token': self.api_token,
                   'Accept': self.content_type}

        url = '{}/reports/report?report_type={}&id={}'.format(self.base_url,
                                                              reportType,
                                                              reportID)

        if self.client_token:
            headers['X-FeClient-Token'] = self.client_token

        if formatPDF:
            headers['Accept'] = 'application/pdf'

        response = requests.get(url, headers=headers, verify=self.verify_SSL)

        if response.status_code == 200:
            pass
        else:
            raise Exception('Unexpected response: {}'.format(response.text))

        return response

    def retrieve_report_by_infectionID(self, infectionID, formatPDF=False,
                                       infectionType='malware-object',
                                       reportType='alertDetailsReport'):

        headers = {'X-FeApi-Token': self.api_token,
                   'Accept': self.content_type}

        url = '{}/reports/report?report_type={}&infection_id={}&infection_type={}'
        url = url.format(self.base_url, reportType, infectionID, infectionType)

        if self.client_token:
            headers['X-FeClient-Token'] = self.client_token

        if formatPDF:
            headers['Accept'] = 'application/pdf'

        response = requests.get(url, headers=headers, verify=self.verify_SSL)

        if response.status_code == 200:
            pass
        else:
            raise Exception('Unexpected response: {}'.format(response.text))

        return response

    def query_configuration(self):

        headers = {'X-FeApi-Token': self.api_token,
                   'Accept': self.content_type}

        url = '{}/config'.format(self.base_url)

        if self.client_token:
            headers['X-FeClient-Token'] = self.client_token

        response = requests.get(url, headers=headers, verify=self.verify_SSL)

        if response.status_code == 200:
            pass
        elif response.status_code == 401:
            raise Exception('Invalid session token')
        else:
            raise Exception('Unexpected response: {}'.format(response.text))

        return response

    def submit_file(self, fileHandle, fileName,
                    profiles=['win7-sp1'],
                    analysisType='2',
                    force='false',
                    timeout='500',
                    application='0',
                    prefetch='1',
                    priority='0'):

        headers = {'X-FeApi-Token': self.api_token,
                   'Accept': self.content_type}

        url = '{}/submissions'.format(self.base_url)

        rawData = {'application': str(application),
                   'timeout': str(timeout),
                   'priority': str(priority),
                   'profiles': profiles,
                   'analysistype': str(analysisType),
                   'force': str(force),
                   'prefetch': str(prefetch)}

        submissionData = ('', json.dumps(rawData), 'application/json')

        # Ensure file handle is at top of file
        fileHandle.seek(0)
        fileData = (fileName, fileHandle.read())

        files = {'options': submissionData,
                 'filename': fileData}

        response = requests.post(url, headers=headers, files=files,
                                 verify=self.verify_SSL)

        if response.status_code == 200:
            pass
        elif response.status_code == 400:
            raise Exception('Filter value invalid')
        else:
            raise Exception('Unexpected response: {}'.format(response.text))

        return response

    def submit_url(self, urls,
                   profiles=['win7-sp1'],
                   analysisType='2',
                   force='false',
                   timeout='500',
                   application='0',
                   prefetch='1',
                   priority='0'):

        headers = {'X-FeApi-Token': self.api_token,
                   'Accept': self.content_type}

        url = '{}/submissions/url'.format(self.base_url)

        # Convert to list if urls are passed as tuple
        if isinstance(urls, tuple):
            urls = list(urls)

        # Lazy check for single url submissions
        # that are not in a list and then convert
        if not isinstance(urls, list):
            urls = [urls]

        rawData = {'urls': urls,
                   'application': str(application),
                   'timeout': str(timeout),
                   'priority': str(priority),
                   'profiles': profiles,
                   'analysistype': str(analysisType),
                   'force': str(force),
                   'prefetch': str(prefetch)}

        submissionData = ('', json.dumps(rawData), 'application/json')
        files = {'options': submissionData}

        response = requests.post(url, headers=headers, files=files,
                                 verify=self.verify_SSL)

        if response.status_code == 200:
            pass
        elif response.status_code == 400:
            raise Exception('Filter value invalid')
        elif response.status_code == 500:
            raise Exception('Server encountered issue, retry later')
        else:
            raise Exception('Unexpected response: {}'.format(response.text))

        return response

    def query_submission_status(self, submissionKey):

        headers = {'X-FeApi-Token': self.api_token,
                   'Accept': self.content_type}

        url = '{}/submissions/status/{}'.format(self.base_url,
                                                submissionKey)

        response = requests.get(url, headers=headers, verify=self.verify_SSL)

        if response.status_code == 200:
            pass
        elif response.status_code == 401:
            raise Exception('Invalid session token')
        elif response.status_code == 404:
            raise Exception('Invalid submission key')
        else:
            raise Exception('Unexpected response: {}'.format(response.text))

        return response

    def retrieve_submission_results(self, submissionKey, infoLevel='extended'):

        headers = {'X-FeApi-Token': self.api_token,
                   'Accept': self.content_type}

        url = '{}/submissions/results/{}'.format(self.base_url,
                                                 submissionKey)

        if infoLevel and (infoLevel in self.valid_info_levels):
            url = '{}?info_level={}'.format(url, infoLevel)

        response = requests.get(url, headers=headers, verify=self.verify_SSL)

        if response.status_code == 200:
            pass
        elif response.status_code == 401:
            raise Exception('Invalid session token')
        elif response.status_code == 404:
            raise Exception('Invalid submission key')
        else:
            raise Exception('Unexpected response: {}'.format(response.text))

        return response

    def logout(self):

        headers = {'X-FeApi-Token': self.api_token,
                   'Accept': self.content_type}

        url = '{}/auth/logout'.format(self.base_url)

        response = requests.post(url, headers=headers, verify=self.verify_SSL)

        if response.status_code == 204:
            pass
        elif response.status_code == 304:
            raise Exception('Missing session token')
        else:
            raise Exception('Unexpected response: {}'.format(response.text))

        return response


class ResponseHandler(object):

    xml_namespaces = {'f': 'http://www.fireeye.com/alert/2011/AlertSchema'}
    valid_response_types = ('json', 'xml', 'text')

    def __init__(self, responseObject, responseType='json'):

        if responseType not in self.valid_response_types:
            raise Exception('Invalid response type specified')

        self.response_type = responseType

        # Check if responseObject is requests response object
        if isinstance(responseObject, requests.models.Response):
            # Process requests response object depending on specified type
            if responseType == 'json':
                try:
                    self.response_object = responseObject.json()
                except ValueError:
                    # Attempt to cleanup malformed or unwanted JSON elements
                    # from FireEye and then use demjson to load the object
                    cleanedObject = re.sub(r'\n\s+', '', responseObject.text)
                    cleanedObject = re.sub(r'\n', '', cleanedObject)
                    cleanedObject = re.sub(r'(\"+)?N/A(\"+)?', '\"N/A\"', cleanedObject)
                    self.response_object = demjson.decode(cleanedObject)
                except:
                    message = 'JSON parsing error of response:\n{}'\
                              .format(responseObject.text)
                    raise Exception(message)
            elif responseType == 'xml':
                self.response_object = lxml.etree.fromstring(responseObject.content)
            elif responseType == 'text':
                self.response_object = responseObject.text
            else:  # placeholder for future types
                self.response_object = responseObject.text
        else:
            self.response_object = responseObject

    def find_md5(self):

        if self.response_type == 'json':
            return self._findMd5JSON()
        elif self.response_type == 'xml':
            return self._findMd5XML()
        else:
            raise Exception('Invalid response type for find md5 method')

    def _findMd5JSON(self):
        malwareSection = self._findMalwareSectionJSON()
        md5_values = self._lookForKeyInJsonList(malwareSection, 'md5sum')
        return md5_values

    def _findMd5XML(self):

        try:
            xpath_value = '/notification/malware/analyis/md5sum/'
            md5_entries = self.response_object.xpath(xpath_value)
        except lxml.etree.XPathEvalError:
            xpath_value = '/f:alerts/f:alert/f:explanation/f:malware-detected/f:malware/f:md5sum'
            md5_entries = self.response_object.xpath(xpath_value, namespaces=self.xml_namespaces)
        except:
            md5_entries = []

        md5_values = [md5.text for md5 in md5_entries]

        return md5_values

    def find_profiles(self):

        if self.response_type == 'json':
            return self._findProfilesJSON()
        elif self.response_type == 'xml':
            return self._findProfilesXML()
        else:
            raise Exception('Invalid response type for find profiles method')

    def _findProfilesJSON(self):
        malwareSection = self._findMalwareSectionJSON()
        profile_values = self._lookForKeyInJsonList(malwareSection, 'profile')
        return profile_values

    def _findProfilesXML(self):

        try:
            xpath_value = '/notification/malware/analysis/profile/name'
            profile_entries = self.response_object.xpath(xpath_value)
        except lxml.etree.XPathEvalError:
            xpath_value = '/f:alerts/f:alert/f:explanation/f:malware-detected/f:malware/f:profile'
            profile_entries = self.response_object.xpath(xpath_value, namespaces=self.xml_namespaces)
        except:
            profile_entries = []

        profile_values = [profile.text for profile in profile_entries]

        return profile_values

    def find_malware_section(self):

        if self.response_type == 'json':
            return self._findMalwareSectionJSON()
        elif self.response_type == 'xml':
            return self._findMalwareSectionXML()
        else:
            raise Exception('Invalid response type for find malware section method')

    def _findMalwareSectionJSON(self):

        malware_sections = []

        alerts = self._lookForListOrDict(self.response_object, 'alert')

        for alert in alerts:
            explanations = self._lookForListOrDict(alert, 'explanation')

            for explanation in explanations:
                malwareDetections = self._lookForListOrDict(explanation,
                                                             'malware-detected')
                for malwareDetected in malwareDetections:
                    malware_sections.extend(self._lookForListOrDict(malwareDetected,
                                                                     'malware'))

        return malware_sections

    def _findMalwareSectionXML(self):

        try:
            xpath_value = '/notification/malware/analysis'
            malware_entries = self.response_object.xpath(xpath_value)
        except lxml.etree.XPathEvalError:
            xpath_value = '/f:alerts/f:alert/f:explanation/f:malware-detected/f:malware'
            malware_entries = self.response_object.xpath(xpath_value, namespaces=self.xml_namespaces)
        except:
            malware_entries = []

        malware_sections = [section.text for section in malware_entries]

        return malware_sections

    def _lookForListOrDict(self, subDict, targetName):

        returnData = []

        if targetName in subDict and subDict[targetName]:
            if isinstance(subDict[targetName], dict):
                returnData = [subDict[targetName]]
            else:
                returnData = subDict[targetName]

        return returnData

    def _lookForKeyInJsonList(self, targetList, targetKey):

        returnData = []

        for entry in targetList:
            if (targetKey in entry) and (entry[targetKey] != ""):
                returnData.append(entry[targetKey])

        return returnData

    def format_JSON(self):

        formattedObject = {}

        # Traversal logic:
        # http://nvie.com/posts/modifying-deeply-nested-structures/
        def traverse(obj):
            if isinstance(obj, dict):
                return {k: traverse(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [traverse(elem) for elem in obj]
            else:
                return obj  # no container, just values (str, int, float)

        if self.response_type != 'json':
            raise Exception('Invalid response object type for format JSON method')

        for key, value in self.response_object.items():
            formattedObject[key] = traverse(value)

        return formattedObject
