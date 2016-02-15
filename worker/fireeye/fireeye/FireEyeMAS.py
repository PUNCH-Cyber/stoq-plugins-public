#!/usr/bin/env python
# pylint: disable=C0103
# pylint: disable=E1101


#######################
#
# FireEye API
#
# requires: requests, IPy and lxml libraries that aren't in the python
#           standard library
#
# Copyright (c) 2015 United States Government/National Institutes of Health
# Author: Aaron Gee-Clough
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
#
#####################

import IPy
import json
import requests
import datetime
import lxml.etree

from io import StringIO
from lxml.etree import iterparse


def checkLoggedIn(method):
    def check(*args, **kwargs):
        instance = args[0]
        if not instance.apiToken:
            instance.__login__()
        return method(*args, **kwargs)
    return check


def testType(name, obj, targetType):
    if not isinstance(obj, targetType):
        raise Exception("%s must be type %s" % (name, targetType))


def testIP(name, ip):
    try:
        IPy.IP(ip)
    except:
        raise Exception("%s was not a valid IP" % name)

valid_durations = ["1_hour",
                   "2_hours",
                   "6_hours",
                   "12_hours",
                   "24_hours",
                   "48_hours",
                   ]

valid_info_levels = ['concise', 'normal', 'extended']

valid_report_types = ["fmpsFileExecutiveSummary",
                      "empsEmailAVReport",
                      "empsEmailActivity",
                      "empsEmailExecutiveSummary",
                      "mpsCallBackServeR",
                      "mpsExecutiveSummary",
                      "mpsMalwareActivity",
                      "mpsWebAVReport"
                      ]

valid_report_durations = ["pastWeek",
                          "pastMonth",
                          "pastThreeMonths",
                          "rangeReport"]

valid_profiles = ['winxp-sp2',
                  'winxp-sp3',
                  'win7-sp1',
                  'win7x64-sp1']

valid_content_types = ["application/json",
                       "application/xml"]


class FireEyeResponse(object):
    def __init__(self, jsonObj=None, xmlObj=None):
        if (jsonObj is None and xmlObj is None):
            raise Exception("must have json or xml entry")
        self.jsonObj = jsonObj
        self.xmlObj = xmlObj
        # I sincerely hate XML sometimes.
        self.namespaces = {'f': 'http://www.fireeye.com/alert/2011/AlertSchema'}

    def _lookForListOrDict(self, subDict, targetName):
        # What's going on here: FireEye Json seems to turns some things,
        # like the "alerts" or "malware" sections of  their json, into lists
        # or dicts rather randomly. This is annoying, so I normalize them
        # all to lists, no matter what they started as. If they're a single
        # dict, this turns them into a single-entry list.
        returnData = []
        if targetName in subDict and subDict[targetName]:
            if isinstance(subDict[targetName], dict):
                returnData = [subDict[targetName]]
            else:
                returnData = subDict[targetName]
        return returnData

    def _lookForKeyInJsonList(self, targetList, key):
        # assumes that the targetList is a list of dicts, looks for
        # that key in any entry of the list.
        returnData = []
        for entry in targetList:
            if (key in entry) and (entry[key] != ""):
                returnData.append(entry[key])
        return returnData

    def _findMalwareSectionJson(self):
        malware = []
        alerts = self._lookForListOrDict(self.jsonObj, "alert")
        for alert in alerts:
            explanations = self._lookForListOrDict(alert, "explanation")
            for explanation in explanations:
                malwareDetections = self._lookForListOrDict(explanation,
                                                            "malware-detected")
                for malwareDetected in malwareDetections:
                    malware.extend(self._lookForListOrDict(malwareDetected,
                                                           "malware"))
        return malware

    def findMD5s(self):
        if self.jsonObj is not None:
            malwaresection = self._findMalwareSectionJson()
            md5s = self._lookForKeyInJsonList(malwaresection, "md5sum")
        elif self.xmlObj is not None:
            try:
                md5Entries = self.xmlObj.xpath("/notification/malware/"
                                               "analyis/md5sum/")
            except lxml.etree.XPathEvalError:
                try:
                    md5Entries = self.xmlObj.xpath("/f:alerts/"
                                                   "f:alert/"
                                                   "f:explanation/"
                                                   "f:malware-detected/"
                                                   "f:malware/"
                                                   "f:md5sum",
                                                   namespaces=self.namespaces)
                except lxml.etree.XPathEvalError:
                    # means the MD5 didn't exist in the path.
                    md5Entries = []
            md5s = []
            for entry in md5Entries:
                md5s.append(entry.text)
        return md5s

    def findProfiles(self):
        if self.jsonObj is not None:
            malwaresection = self._findMalwareSectionJson()
            # is this a typo
            profiles = self._lookForKeyInJsonList(malwaresection, "profile")
        elif self.xmlObj is not None:
            try:
                profileEntries = self.xmlObj.xpath("/notification/malware/"
                                                   "analysis/profile/name")
            except lxml.etree.XPathEvalError:
                profileEntries = []
            # xpath might return an empty list if they're using a namespace.
            if profileEntries == []:
                try:
                    profileEntries = self.xmlObj.xpath("/f:alerts/f:alert/"
                                                       "f:explanation/"
                                                       "f:malware-detected/"
                                                       "f:malware/"
                                                       "f:profile",
                                                       namespaces=self.namespaces)
                except lxml.etree.XPathEvalError:
                    pass
            profiles = []
            for entry in profileEntries:
                profiles.append(entry.text)
        return profiles


class FireEyeServer(object):
    def __init__(self,
                 server,
                 username,
                 password,
                 apiVersion,
                 partnerToken=None,
                 responseContentType="application/json",
                 autoParseResponses=True,
                 verifySSL=True):
        # make sure the url is slash-terminated
        if not server.endswith("/"):
            server = server + "/"
        self.server = server
        self.username = username
        self.password = password
        self.apiVersion = apiVersion
        self.apiToken = None
        self.partnerToken = partnerToken
        if responseContentType not in valid_content_types:
            raise Exception("responseContentType can only be "
                            "one of %s" % valid_content_types)
        self.responseContentType = responseContentType
        self.autoParseResponses = autoParseResponses
        self.verifySSL = verifySSL

    def __login__(self):
        url = self._buildURL("auth/login?")
        if self.partnerToken:
            headers = {"X-FeClient-Token": self.partnerToken}
        else:
            headers = {}
        response = requests.post(url,
                                 auth=(self.username, self.password),
                                 headers=headers, verify=self.verifySSL)
        if response.status_code != 200:
            raise Exception("Bad username or password "
                            "supplied: %s" % response.text)
        apiToken = response.headers["X-FeApi-Token"]
        self.apiToken = apiToken
        return

    def _buildURL(self, endbit):
        url = "https://" + self.server + "wsapis/%s/%s" % (self.apiVersion,
                                                           endbit)
        return url

    def _buildHeaders(self):
        headers = {'X-FeApi-Token': self.apiToken,
                   'Accept': self.responseContentType}
        if self.partnerToken:
            headers['X-FeClient-Token'] = self.partnerToken
        return headers

    def _parseResponse(self, response):
        if not self.autoParseResponses:
            return response.text
        elif self.responseContentType == "application/json":
            try:
                data = response.json()
            except:
                raise Exception("error parsing json. "
                                "Raw response: %s" % response.raw.read())
        elif self.responseContentType == "application/xml":
            data = iterparse(response.raw)
        else:
            raise Exception("parsing response, but no idea how to..."
                            "autoparse set to True, but not json or xml")
        return data

    def __makeReponseObj(self, xmldata=None, jsondata=None):
        if not (xmldata or jsondata):
            raise Exception("need xml or json")
        elif xmldata:
            returnObj = FireEyeResponse(xmlObj=xmldata)
        elif jsondata:
            returnObj = FireEyeResponse(jsonObj=jsondata)
        else:
            raise Exception("???")
        return returnObj

    def _doGetRequest(self, url, stream=False, params=None):
        # would do this in a loop, but really it should only happen twice,
        # and then exception. So there's no point in overcomplicating this.
        headers = self._buildHeaders()
        response = requests.get(url,
                                headers=headers,
                                params=params,
                                verify=self.verifySSL)
        if response.status_code == 401:
            self.__login__()
            headers = self._buildHeaders()
            response = requests.get(url,
                                    headers=headers,
                                    params=params,
                                    stream=stream,
                                    verify=self.verifySSL)
            if response.status_code == 401:
                raise Exception("unauthorized response...try a new password")
        return response

    def _doPostRequest(self, url, stream=False, files=None, data=None):
        headers = self._buildHeaders()
        response = requests.post(url,
                                 stream=stream,
                                 files=files,
                                 data=data,
                                 headers=headers,
                                 verify=self.verifySSL)
        if response.status_code == 401:
            self.__login__()
            headers = self._buildHeaders()
            response = requests.post(url,
                                     stream=stream,
                                     files=files,
                                     data=data,
                                     headers=headers,
                                     verify=self.verifySSL)
            if response.status_code == 401:
                raise Exception("unauthorized response...try a new password")
        return response

    def logout(self):
        url = self._buildURL("auth/logout")
        self._doPostRequest(url)
        return

    @checkLoggedIn
    def getAlert(self,
                 start_time=None,
                 end_time=None,
                 duration=None,
                 src_ip=None,
                 dst_ip=None,
                 malware_name=None,
                 malware_type=None,
                 sender_email=None,
                 recipient_email=None,
                 file_name=None,
                 file_type=None,
                 url=None,
                 md5=None,
                 callback_domain=None,
                 info_level="extended"):
        # note: expected times to be datetime objects with timezones set
        # duration must be one of the valid_durations listed above
        # info_level can only be "concise", "normal" or "extended"
        args = {}
        if start_time:
            testType("start_time", start_time, datetime.datetime)
            # if timezone defined, isoformat returns exactly what FireEye is
            # looking for. If not, it's a bit of a mess.
            if not start_time.tzinfo:
                raise Exception("start_time must have timezone defined")
            if end_time:
                raise Exception("can't specify start and end time together.")
            args['start_time'] = start_time.isoformat()
        if end_time:
            testType("end_time", end_time, datetime.datetime)
            # see comment above for start time
            if not end_time.tzinfo:
                raise Exception("end_time must have timezone defined")
            if start_time:
                raise Exception("can't specify start and end time together")
            args['end_time'] = end_time.isoformat()
        if duration:
            if not (start_time or end_time):
                raise Exception("duration specified, but no start or end time")
            if duration not in valid_durations:
                raise Exception("duration must be "
                                "one of: %s" % valid_durations)
            args['duration'] = duration
        if src_ip:
            testIP('src_ip', src_ip)
            args['src_ip'] = src_ip
        if dst_ip:
            testIP('dst_ip', dst_ip)
            args['dst_ip'] = dst_ip
        if malware_name:
            testType("malware_name", malware_name, basestring)
            args['malware_name'] = malware_name
        if malware_type:
            testType("malware_type", malware_type, basestring)
            args['malware_type'] = malware_type
        if sender_email:
            # yes ,I could check more thoroughly.
            testType("sender_email", sender_email, basestring)
            args['sender_email'] = sender_email
        if recipient_email:
            testType("recipient_email", recipient_email, basestring)
            args['recipient_email'] = recipient_email
        if file_name:
            testType("file_name", file_name, basestring)
            args['file_name'] = file_name
        if file_type:
            testType("file_type", file_type, basestring)
            args['file_type'] = file_type
        if url:
            testType("url", url, basestring)
            args['url'] = url
        if md5:
            testType("md5", md5, basestring)
            args['md5'] = md5
        if callback_domain:
            testType("callback_domain", callback_domain, basestring)
            args['callback_domain'] = callback_domain
        if info_level:
            if info_level not in valid_info_levels:
                raise Exception("Info level must be "
                                "one of: %s" % valid_info_levels)
            args['info_level'] = info_level
        # error checking done, now for the actual work
        url = self._buildURL("alerts")
        response = self._doGetRequest(url, params=args)
        data = self._parseResponse(response)
        parsedObj = self.__makeReponseObj(data)
        return parsedObj

    @checkLoggedIn
    def getReport(self, report_type, duration, start_date=None, end_date=None):
        # Note: this will return a StringIO file-like object. It's up to the
        # user to save this file somewhere.
        # going to assume that start_date and end_date are datetime objects
        # with timezones set
        if report_type not in valid_report_types:
            raise Exception("report_type must be"
                            " one of %s" % valid_report_types)
        if duration not in valid_report_durations:
            raise Exception("report duration must be"
                            " one of: %s" % valid_report_durations)
        if duration == "rangeReport":
            if not (start_date and end_date):
                raise Exception("range report specified, but start and/or"
                                " end time missing")
            if not start_date.tzinfo:
                raise Exception("start date must have time zone set.")
            if not end_date.tzinfo:
                raise Exception("end_date must have time zone set")
            testType("start_date", start_date, datetime.datetime)
            testType("end_date", end_date, datetime.datetime)

            url = self._buildURL("MPS/%s/%s/%s/%s" % (report_type,
                                                      duration,
                                                      start_date.isoformat(),
                                                      end_date.isoformat()))
        else:
            url = self._buildURL("MPS/%s/%s" % (report_type, duration))
        response = self._doGetRequest(url, stream=True)
        outputFile = StringIO()
        for block in response.iter_content(1024):
            if not block:
                break
            outputFile.write(block)
        return outputFile

    @checkLoggedIn
    def getConfiguration(self):
        url = self._buildURL("config")
        response = self._doGetRequest(url)
        return self._parseResponse(response)

    @checkLoggedIn
    def getSubmission(self, submissionID):
        url = self._buildURL("submissions/results/%s?info_level=extended" % submissionID)
        response = self._doGetRequest(url)
        data = self._parseResponse(response)
        responseObj = self.__makeReponseObj(jsondata=data)
        return responseObj

    @checkLoggedIn
    def getSubmissionStatus(self, submissionID):
        url = self._buildURL("submissions/status/%s" % submissionID)
        response = self._doGetRequest(url)
        return response.text

    @checkLoggedIn
    def submitFile(self,
                   fileHandle,
                   file_name,
                   profiles,
                   analysis_type,
                   force,
                   timeout,
                   application,
                   prefetch,
                   priority):
        raise NotImplementedError


class FireEyeServerv100(FireEyeServer):
    def __init__(self,
                 server,
                 username,
                 password,
                 partnerToken=None,
                 responseContentType="application/json",
                 autoParseResponses=True,
                 verifySSL=True
                 ):
        super().__init__(server,
                         username,
                         password,
                         "v1.0.0",
                         partnerToken,
                         responseContentType,
                         autoParseResponses,
                         verifySSL)

    def submitFile(self,
                   fileHandle,
                   file_name,
                   profiles,
                   analysis_type=0,
                   force="false",
                   timeout=500,
                   application=0,
                   prefetch=0,
                   priority=0):
        # I don't like hardcoding 0 or 1, but that's what the API is
        # looking for.
        if analysis_type not in (0, 1):
            raise Exception("analysis_type must be 0 (for live) or 1"
                            " (for sandbox)")
        if force not in ("false", "true"):
            raise Exception("force must be \"false\" or \"true\"")
        if prefetch not in (0, 1):
            raise Exception("prefetch must be 0 (for false) or 1 (for true)")
        if priority not in (0, 1):
            raise Exception("priority must be 0 (for normal) or 1 (for high)")
        testType("profiles", profiles, list)
        for profile in profiles:
            if profile not in valid_profiles:
                raise Exception("profile must be one of: %s" % valid_profiles)
        testType("application", application, int)
        url = self._buildURL("submissions")
        # for reasons I don't understand, the API wants all numbers
        # as strings in the json that's sent.
        data = {"analysistype": str(analysis_type),
                "profiles": profiles,
                "force": str(force),
                "timeout": str(timeout),
                "application": str(application),
                "prefetch": str(prefetch),
                "priority": str(priority)
                }
        options = {"options": json.dumps(data)}
        files = {"filename": (file_name, fileHandle)}
        response = self._doPostRequest(url, data=options, files=files)
        return response


class FireEyeServerv110(FireEyeServer):
    def __init__(self,
                 server,
                 username,
                 password,
                 partnerToken=None,
                 responseContentType="application/json",
                 autoParseResponses=True,
                 verifySSL=True
                 ):
        super().__init__(server,
                         username,
                         password,
                         "v1.1.0",
                         partnerToken,
                         responseContentType,
                         autoParseResponses,
                         verifySSL)

    def submitFile(self,
                   fileHandle,
                   file_name,
                   profiles,
                   analysis_type=2,
                   force="false",
                   timeout=500,
                   application=-1,
                   prefetch=1,
                   priority=0):
        # I don't like hardcoding 0 or 1, but that's what the API is
        # looking for.
        if analysis_type not in (1, 2):
            raise Exception("analysis_type must be 1 (for live) or 2"
                            " (for sandbox)")
        if force not in ("false", "true"):
            raise Exception("force must be \"false\" or \"true\"")
        if prefetch not in (0, 1):
            raise Exception("prefetch must be 0 (for false) or 1 (for true)")
        if priority not in (0, 1):
            raise Exception("priority must be 0 (for normal) or 1 (for high)")
        testType("profiles", profiles, list)
        for profile in profiles:
            if profile not in valid_profiles:
                raise Exception("profile must be one of: %s" % valid_profiles)
        testType("application", application, int)
        url = self._buildURL("submissions")
        # just in case, rewind the filehandle to the top of the file.
        fileHandle.seek(0)
        # for reasons I don't understand, the API wants all numbers
        # as strings in the json that's sent.
        data = {"analysistype": str(analysis_type),
                "profiles": profiles,
                "force": str(force),
                "timeout": str(timeout),
                "application": str(application),
                "prefetch": str(prefetch),
                "priority": str(priority)
                }
        files = {"options": ("", json.dumps(data), "application/json"),
                 # I really don't like doing it this way, but I'm running into
                 # a problem with Django, where I'm using this library,
                 # where the fileHandle read in a submitted file ends up
                 # being read as empty. So, the submitted file to Fireeye
                 # is an empty file. Having requests treat them both
                 # as strings fixed that, but I really dislike this.
                 "filename": (file_name, fileHandle.read())
                 }
        response = self._doPostRequest(url, files=files)
        return response
