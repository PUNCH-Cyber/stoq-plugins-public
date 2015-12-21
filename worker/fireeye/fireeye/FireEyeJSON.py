#######################
#
# FireEye JSON
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

def fixFireEyeJSON(target):
    # the plan: build a new dictionary from the existing dictionary.
    # for any given dictionary entry,
    # if it's value is another dictionary,
    #    then make it a list with that dictionary as the only value,
    #     then recurse through each value to make sure that this problem
    #        isn't recurring lower down
    # if its value is a list, then make a list in the new value,
    #     then walk each value in the list & recurse through the original
    #       list to make sure the values work
    # if it's just a base value (string, integer, float),
    #    then copy the value into the new dictionary.
    #
    # None of this would be necessary if fireeye would just be
    # consistent about their JSON
    #
    #
    if isinstance(target, list):
        response = []
        for entry in target:
            response.append(fixFireEyeJSON(entry))
    elif isinstance(target, dict):
        response = {}
        for key in target:
            if isinstance(target[key], (str, bytes)):
                if not target[key]:
                    continue
                response[key] = target[key]
            elif isinstance(target[key], int):
                response[key] = target[key]
            elif isinstance(target[key], float):
                response[key] = target[key]
            elif isinstance(target[key], list):
                if not target[key]:
                    continue
                response[key] = []
                for entry in target[key]:
                    response[key].append(fixFireEyeJSON(entry))
            elif isinstance(target[key], dict):
                if not target[key]:
                    continue
                response[key] = []
                response[key].append(fixFireEyeJSON(target[key]))
    else:
        response = target
    return response
