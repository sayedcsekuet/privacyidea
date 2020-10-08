# -*- coding: utf-8 -*-
#
#  Mar, 12 2020 Bruno Cascio
#  http://www.privacyidea.org
#
#  product:  PrivacyIDEA
#  module:   httpresolver
#  tool:     HTTPResolver
#  edition:  Comunity Edition
#
#  License:  AGPLv3
#  contact:  http://www.linotp.org
#            http://www.lsexperts.de
#            linotp@lsexperts.de
#
# This code is free software; you can redistribute it and/or
# modify it under the terms of the GNU AFFERO GENERAL PUBLIC LICENSE
# License as published by the Free Software Foundation; either
# version 3 of the License, or any later version.
#
# This code is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU AFFERO GENERAL PUBLIC LICENSE for more details.
#
# You should have received a copy of the GNU Affero General Public
# License along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

from .UserIdResolver import UserIdResolver
import requests
import logging
import json
from six.moves.urllib.parse import urlencode
from pydash import get
from privacyidea.api.lib.utils import getParam

ENCODING = "utf-8"

__name__ = "HTTP_RESOLVER"

log = logging.getLogger(__name__)


class HTTPResolver(UserIdResolver):

    fields = {
        "listEndpoint": 1,
        "listMethod": 1,
        "listRequestMapping": 1,
        "listHeaders": 1,
        "listResponseMapping": 1,
        "endpoint": 1,
        "method": 1,
        "requestMapping": 1,
        "headers": 1,
        "responseMapping": 1,
        "hasSpecialErrorHandler": 0,
        "errorResponse": 0,
        "limit": 1
    }

    def __init__(self):
        super(HTTPResolver, self).__init__()
        self.config = {}

    @staticmethod
    def getResolverClassType():
        """
        provide the resolver type for registration
        """
        return 'httpresolver'

    @staticmethod
    def getResolverType():
        """
        getResolverType - return the type of the resolver

        :return: returns the string 'ldapresolver'
        :rtype:  string
        """
        return HTTPResolver.getResolverClassType()

    @classmethod
    def getResolverClassDescriptor(cls):
        """
        return the descriptor of the resolver, which is
        - the class name and
        - the config description

        :return: resolver description dict
        :rtype:  dict
        """
        descriptor = {}
        typ = cls.getResolverClassType()
        descriptor['clazz'] = "useridresolver.HTTPResolver.HTTPResolver"
        descriptor['config'] = {
            'listEndpoint': 'string',
            'listMethod': 'string',
            'listHeaders': 'string',
            'listRequestMapping': 'string',
            'listResponseMapping': 'string',
            'endpoint': 'string',
            'method': 'string',
            'headers': 'string',
            'requestMapping': 'string',
            'responseMapping': 'string',
            'hasSpecialErrorHandler': 'bool',
            'errorResponse': 'string',
            'limit': 'string'
        }
        return {typ: descriptor}

    @staticmethod
    def getResolverDescriptor():
        """
        return the descriptor of the resolver, which is
        - the class name and
        - the config description

        :return: resolver description dict
        :rtype:  dict
        """
        return HTTPResolver.getResolverClassDescriptor()

    def getUserId(self, loginName):
        """
        This method only echo's the loginName parameter
        """
        return loginName

    def getUsername(self, userid):
        """
        This method only echo's the userid parameter
        """
        return userid

    def getUserInfo(self, userid):
        """
        This function returns all user information for a given user object
        identified by UserID.
        :param userid: ID of the user in the resolver
        :type userid: int or string
        :return:  dictionary, if no object is found, the dictionary is empty
        :rtype: dict
        """
        return self._getUser(userid)

    def getUserList(self, searchDict=None):
        """
        Since it is an HTTP resolver,
        users are not stored in the database
        """
        if searchDict is None:
            searchDict = {}
        if ("username" in searchDict) and (searchDict['username'].find('*') == -1):
            user=self._getUser(searchDict['username'])
            listUsers=[user]
        else:
            listUsers=self._getListData(searchDict)

        return listUsers

    def getResolverId(self):
        """
        get resolver specific information
        :return: the resolver identifier string - empty string if not exist
        """
        return self.config['endpoint'] if 'endpoint' in self.config else ''

    def loadConfig(self, config):
        """
        Load the configuration from the dict into the Resolver object.
        If attributes are missing, need to set default values.
        If required attributes are missing, this should raise an
        Exception.

        :param config: The configuration values of the resolver
        :type config: dict
        """
        self.config = config
        return self

    @classmethod
    def testconnection(cls, param):
        """
        This function lets you test if the parameters can be used to create a
        working resolver. Also, you can use it anytime you see if the API is
        running as expected.
        The implementation should try to make a request to the HTTP API and verify
        if user can be retrieved.
        In case of success it should return the raw http response.

        :param param: The parameters that should be saved as the resolver
        :type param: dict
        :return: returns True in case of success and a raw response
        :rtype: tuple
        """
        desc = {}
        paramData={}
        success = False
        try:
            resolver = HTTPResolver()
            resolver.loadConfig(param)
            paramData['userid']=param.get('testUser')
            desc['userInfoResponse']=resolver._getUser(param.get('testUser'))
            desc['userListResponse']=resolver._getListData(paramData)
            success = True
        except Exception as e:
            success = False
            desc = "failed: {0!s}".format(e)
        return success, desc

    #
    #   Private methods
    #
    def _getUser(self, userid):
        param = self.config
        method = param.get('method').lower()
        endpoint = param.get('endpoint').replace("{userid}", userid)
        requestMappingJSON = json.loads(param.get('requestMapping').replace("{userid}", userid))
        responseMapping = json.loads(param.get('responseMapping'))
        headers = json.loads(param.get('headers', '{}'))

        jsonHTTPResponse = self._sendHttpRequest(endpoint, method, requestMappingJSON, headers)
        if isinstance(jsonHTTPResponse, dict):
            data=jsonHTTPResponse
        else:
            data= jsonHTTPResponse[0]

        self._createSpecialError(data, userid)
        return self._mapData(responseMapping, data)

    def _getListData(self, searchDict=None ):
        param = self.config
        method = param.get('listMethod').lower()
        endpoint = param.get('listEndpoint')
        requestMappingJSON = self._filterData(self._mapData(json.loads(param.get('listRequestMapping')),searchDict))
        limit = param.get('limit',1000)
        requestMappingJSON['limit']=param.get('limit',1000)
        headers = json.loads(param.get('listHeaders', '{}'))
        responseMapping = json.loads(param.get('listResponseMapping'))
        jsonHTTPResponse = self._sendHttpRequest(endpoint, method, requestMappingJSON, headers)
        users=[]
        for userData in jsonHTTPResponse:
            user=self._mapData(responseMapping, userData)
            if "id" in user:
                user['editable']=False
                users.append(user)
        return users

    def _sendHttpRequest(self, endpoint, method, requestParams={}, headers={} ):
        method = method.lower()
        if method == "post":
            httpResponse = requests.post(endpoint, json=requestParams, headers=headers)
        else:
            httpResponse = requests.get(endpoint, urlencode(requestParams), headers=headers)

        # Raises HTTPError, if one occurred.
        httpResponse.raise_for_status()
        jsonHTTPResponse = httpResponse.json()
        return jsonHTTPResponse

    def _mapData(self, mapping, data):
        # Create mapped response with response mapping resolver input
        response={}
        for pi_user_key, value in mapping.items():
            if value.startswith('{') and value.endswith('}'):
                response[pi_user_key] = get(data, value[1:-1])
            else:
                response[pi_user_key] = value
        return response

    def _filterData(self, data, find='*', replace=''):
        if data == None:
            return data
        # Create mapped response with response mapping resolver input
        response={}
        for key, value in data.items():
            if value == None:
                continue
            response[key] = value.replace(find,replace)
        return response

    def _createSpecialError(self, responseData, userid):
        param = self.config
        hasSpecialErrorHandler = bool(param.get('hasSpecialErrorHandler'))
        errorResponse = json.loads(param.get('errorResponse', '{}'))
        if hasSpecialErrorHandler and len(errorResponse.items()):
            # verify if error response mapping is a subset of the json http response
            if all([x in responseData.items() for x in errorResponse.items()]):
                log.error(responseData)
                raise Exception('Received an error while searching for user: %s' % userid)
