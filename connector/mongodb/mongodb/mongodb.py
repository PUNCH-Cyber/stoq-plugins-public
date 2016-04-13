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

Sends and retrieves content from MongoDB

"""

from gridfs import GridFS
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError
from gridfs.errors import FileExists

from stoq.scan import get_sha1
from stoq.plugins import StoqConnectorPlugin


class MongoConnector(StoqConnectorPlugin):

    def __init__(self):
        super().__init__()

    def activate(self, stoq):
        self.stoq = stoq

        super().activate()

        self.archive = False

    def get_file(self, **kwargs):
        """
        Retrieve a file from GridFS

        :param **kwargs md5: md5 hash of payload to be retrieved
        :param **kwargs sha1: SHA1 hash of payload to be retrieved
        :param **kwargs sha256: SHA256 hash of payload to be retrieved
        :param **kwargs sha512: SHA512 hash of payload to be retrieved

        :returns: Content of file retrieved
        :rtype: bytes or None

        """

        # Make sure we only use GridFS
        self.archive = True

        # What keys are OK to use to validate if a file exists and retrieve it?
        valid_keys = ['sha1', 'md5', 'sha256', 'sha512']

        # Iterate over each valid key and see if it exists in the arguments
        # passed
        for key in valid_keys:
            if key in kwargs:
                # Make sure we have a valid mongodb connection
                self.connect()

                # So gridfs' documentation states we can use find_one, but
                # it doesn't exist. So instead, we are going to use find,
                # then just use the first item in the index, since we 
                # should always only return a single result anyway.
                results = self.collection.find({key: kwargs[key]})

                if results.count:
                    try:
                        with self.collection.get(results[0]._id) as requested_file:
                            return requested_file.read()
                    except Exception as e:
                        self.stoq.log.error("Unable to retrieve file "
                                            "{0} :: {1}".format(kwargs, str(e)))
                        return None

        # No results, carry on.
        return None

    def api_query(self, query):
        """
        Handle queries from the API

        :param dict query: API request containing the mongodb query

        :returns: dict containing results or None
        :rtype: dict or None

        Example API Query looking for yara results for a specific MD5 hash:

        { "collections": ["yara"],
          "parameters": {"md5": "0eb8242cb22e19ba1ca0d5b9affc7af0"},
          "apikey": "API_KEY" }

        """

        for query_attempt in range(3):
            try:
                query_results = []
                search_results = []
                results = {}

                # Define the collections to search and the parameters
                collections = query['collections']
                parameters = query['parameters']

                # Iterate over each collection and search
                for collection in collections:
                    # Make sure the collection we are searching is permitted
                    if collection in self.api_collections_list:
                        searchterm = {}

                        # Iterate over the keys and validate they are permitted
                        for parameter, value in parameters.items():
                            if parameter in self.api_keys_list:
                                searchterm[parameter] = value

                        if collection == "gridfs":
                            # Ensure we connect to GridFS
                            self.archive = True

                            self.__connect_gridfs(collection_name="fs.files")

                        else:
                            # Make sure this is set to False so we don't
                            # connect to GridFS
                            self.archive = False

                            # Define the mongo collection based on the name of
                            # the collection identified in the request
                            self.__connect_mongodb(collection_name=collection)

                        # Do our search
                        query_results = self.collection.find(searchterm)

                        # Iterate over the search results and store them in a
                        # list
                        for query_result in query_results:
                            # Let's remove the _id key as it should never be
                            # needed by the end user
                            query_result.pop("_id", None)
                            search_results.append(query_result)

                # Construct the response
                results['results'] = search_results
                results['count'] = len(search_results)
                results['parameters'] = parameters
                results['collections'] = collections
                return results

            except:
                self.connect()

        return None

    def save(self, payload, archive=False, **kwargs):
        """
        Save results to mongodb

        :param dict/bytes payload: Content to be inserted into mongodb
        :param bool archive: Define whether the payload to be inserted as a
                             binary sample that should be saved in GridFS.
        :param **kwargs sha1: SHA1 hash of payload. Used with saving results
                              as well as payloads to GridFS. Automatically
                              generated if not value is provided.
        :param **kwargs index: Index name to save content to
        :param **kwargs *: Any additional attributes that should be added
                           to the GridFS object on insert

        """

        self.archive = archive

        # Define the index name, if available. 
        index = kwargs.get('index', None)

        if not hasattr(self, 'collection'):
            self.connect(index)

        # Let's attempt to save our data to mongo at most 3 times. The very
        # first time, this will always fail because we haven't made a
        # connection to mongodb or gridfs yet.
        for save_attempt in range(3):
            try:
                if self.archive:
                    # Assign the indexed _id key to be that of the sha1 for the
                    # file.  This will eliminate duplicate files stored within
                    # GridFS.
                    if save_attempt == 0:
                        kwargs['_id'] = kwargs['sha1']
                    try:
                        # Attempt to insert the payload into GridFS
                        with self.collection.new_file(**kwargs) as fp:
                            fp.write(payload)
                        break
                    except (DuplicateKeyError, FileExists):
                        # Looks like the file is a duplicate, let's just
                        # continue on.
                        break
                else:
                    # Check to see if we have a sha1 in the payload to be
                    # saved. If not, let's hash the payload with sha1.
                    try:
                        payload['_id'] = kwargs['sha1']
                    except KeyError:
                        payload['_id'] = get_sha1(payload)

                    try:
                        # Attempt to insert
                        self.collection.insert(payload)
                    except DuplicateKeyError:
                        # Looks like our insert failed due to a Duplicate key.
                        # Let's go ahead and update the results key with our
                        # new results rather than create a new record.
                        for result in payload['results']:
                            self.collection.update({'_id': payload['_id']},
                                                   {'$push':
                                                    {'results': result}})

                # There is no sense in copy()'ing the payload dict, just to
                # remove the _id. Let's just pop() since we only require it for
                # the mongodb primary key.
                payload.pop('_id')

                # Success..let's break out of our loop.
                break
            except:
                # We probably don't have a valid MongoDB connection. Time to
                # make one.
                self.connect(index)

        super().save()

    def connect(self, collection_name=None):
        """
        Connect to a mongodb instance

        :param bytes collection: Name of MongoDB collection to utilize

        """

        # self.conn is defined in the stoq plugin config file.
        self.mongo_client = MongoClient(self.conn)

        if self.archive:
            self.__connect_gridfs(collection_name)
        else:
            self.__connect_mongodb(collection_name)

        super().connect()

    def __connect_gridfs(self, collection_name=None):
        # We are handling an archived sample with GridFS
        self.gridfs_db = self.mongo_client.stoq_gridfs

        # No collection, we assume that the query is for binary data
        if not collection_name:
            self.collection = GridFS(self.gridfs_db)
        else:
            # We have a collection, let's use it to query/update metadata
            self.collection = self.gridfs_db[collection_name]

    def __connect_mongodb(self, collection_name=None):
        # If no collection name was passed, let's set it to the name of the
        # worker plugin that called us
        if not collection_name:
            collection_name = self.parentname

        # No, we are saving a json document from a plugin
        self.mongo_db = self.mongo_client.stoq
        self.collection = self.mongo_db[collection_name]

    def disconnect(self):
        """
        Disconnect from mongodb instance

        """

        self.mongo_client.disconnect()
        super().disconnect()

