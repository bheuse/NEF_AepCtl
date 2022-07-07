#! /usr/bin/python3

from typing import Union
import requests
import json
import os
import sys
import getopt
import re
import xmltodict
import urllib3
import unittest
import datetime
import base64
from rich.console import Console
from rich.markdown import Markdown
import Util as ut
import Util_GUI as utg
from prompt_toolkit import PromptSession
from prompt_toolkit import print_formatted_text, HTML
from prompt_toolkit.history import FileHistory
from prompt_toolkit.completion import NestedCompleter
from prompt_toolkit.completion import PathCompleter
from prompt_toolkit.contrib.completers.system import SystemCompleter

###
### Logging
###

import logging
logging.basicConfig(format='%(levelname)s:%(name)s:%(message)s', level=logging.INFO)

timestamp = datetime.datetime.now().strftime("%y%m%d-%H%M%S")
logFile   = "."+os.sep+"data_model_to_openapi.log"
logging.basicConfig(filename=logFile, filemode='w', format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.DEBUG)
# ut.setup_logging()

logger = logging.getLogger(__name__)

###
### Globals
###

# HOME : Where the configuration is stored
# WORK : Where the runtime data  is stored
# ROOT : Where the applications and static data are installed

AEPCTL_ROOT_DIR      = os.getcwd()
AEPCTL_HOME_DIR      = os.path.expanduser('~') + os.sep + ".aepctl"  # HOME Directory
AEPCTL_WORK_DIR      = os.getcwd()


if (not os.path.exists(AEPCTL_HOME_DIR)):
    ut.safeCreateDir(AEPCTL_HOME_DIR)

if (not os.path.exists(AEPCTL_WORK_DIR)):
    ut.safeCreateDir(AEPCTL_WORK_DIR)
    ut.safeCreateDir(AEPCTL_WORK_DIR + os.sep + "etc")
    ut.safeCreateDir(AEPCTL_WORK_DIR + os.sep + "data")


CONFIG_DIRECTORY   = AEPCTL_WORK_DIR + os.sep + "etc"
DATA_DIRECTORY     = AEPCTL_WORK_DIR + os.sep + "data"
TMP_DIRECTORY      = AEPCTL_WORK_DIR + os.sep + "tmp"
TEST_DIRECTORY     = AEPCTL_WORK_DIR + os.sep + "tests"
LOGS_DIRECTORY     = AEPCTL_WORK_DIR + os.sep + "logs"
SCRIPTS_DIRECTORY  = AEPCTL_WORK_DIR + os.sep + "scripts"


WSO2_SERVER     = "https://localhost:9443"
CATALOG_SERVER  = "http://localhost:30106"
USERS_SERVER    = "http://localhost:30107"

BACKUP_DIRECTORY = AEPCTL_ROOT_DIR + os.sep + "backup"
STORE_DIRECTORY  = AEPCTL_ROOT_DIR + os.sep + "store"
STORES_FILE      = CONFIG_DIRECTORY + os.sep + "stores.json"
CONFIG_FILE      = None


###
### Configuration
###

def_AEPCTL_Configuration = ut.SuperDict(name="AEPCTL_DefaultConfiguration", data=
{
    "Description"                  : "Default AEPCTL Configuration",
    "WSO2_SERVER"                  : WSO2_SERVER,
    "CATALOG_SERVER"               : CATALOG_SERVER,
    "USERS_SERVER"                 : USERS_SERVER,
    "BACKUP_DIRECTORY"             : BACKUP_DIRECTORY,
    "STORE_DIRECTORY"              : STORE_DIRECTORY,
    "STORES_FILE"                  : STORES_FILE
})
AEPCTL_Configuration_FileName = AEPCTL_HOME_DIR + os.sep + 'AEPCTL_Configuration.json'
AEPCTL_Configuration = ut.SuperDict()

###
### Rest Services List
###

###
### Wso2
###


class Wso2UsersManager:

    def __init__(self, authorization="YWRtaW46YWRtaW4="):
        self.authorization           = authorization
        self.last_operation          = "Nope"
        self.last_operation_code     = 200
        self.last_operation_error    = ""
        self.last_operation_details  = ""
        self.last_operation_response = ""
        self.last_operation_headers  = ""
        self.last_operation_payload  = ""
        self.last_operation_text     = ""

    def __str__(self):
        return str(self.last_operation_response)

    def settings_get(self):
        settings = ut.SuperDict(name="ADMIN SETTINGS")
        settings["ERROR"] = "Not Implemented"
        return settings.getAsData()

    def add_user(self, userName: str, credential: str, roleList : str, requirePasswordChange : bool = False):
        self.last_operation = "Add User : "+userName
        headers = {
            'Authorization': 'Basic '+self.authorization,
            'Content-Type': 'text/xml;charset=UTF-8',
            'SOAPAction': 'urn:addUser',
        }
        payload_xml = """
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" 
                          xmlns:ser="http://service.ws.um.carbon.wso2.org" 
                          xmlns:xsd="http://common.mgt.user.carbon.wso2.org/xsd">
           <soapenv:Header>
           </soapenv:Header>       
           <soapenv:Body>
              <ser:addUser>
                 <!--Optional:-->
                 <ser:userName>"""+userName+"""</ser:userName>
                 <!--Optional:-->
                 <ser:credential>"""+credential+"""</ser:credential>
                 <!--Zero or more repetitions:-->
                 <ser:roleList>"""+roleList+"""</ser:roleList>
                 <!--Optional:-->
                 <ser:requirePasswordChange>"""+str(requirePasswordChange)+"""</ser:requirePasswordChange>
              </ser:addUser>
           </soapenv:Body>
        </soapenv:Envelope>
        """
        return self.handle_request(headers, payload_xml)

    def list_users(self):
        self.last_operation = "List Users"
        headers = {
            'Authorization': 'Basic '+self.authorization,
            'Content-Type': 'text/xml;charset=UTF-8',
            'SOAPAction': 'urn:listUsers',
        }
        payload_xml = """
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" 
                          xmlns:ser="http://service.ws.um.carbon.wso2.org" 
                          xmlns:xsd="http://common.mgt.user.carbon.wso2.org/xsd">
           <soapenv:Header>
           </soapenv:Header>       
           <soapenv:Body>
              <ser:listUsers>
                 <!--Optional:-->
                 <ser:filter>*</ser:filter>          
                 <!--Optional:-->
                 <ser:maxItemLimit>10</ser:maxItemLimit>
              </ser:listUsers>
           </soapenv:Body>
        </soapenv:Envelope>
        """
        return self.handle_request(headers, payload_xml)

    def delete_user(self, userName: str):
        self.last_operation = "Delete User : "+userName
        headers = {
            'Authorization': 'Basic '+self.authorization,
            'Content-Type': 'text/xml;charset=UTF-8',
            'SOAPAction': 'urn:deleteUser',
        }
        payload_xml = """
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" 
                          xmlns:ser="http://service.ws.um.carbon.wso2.org" 
                          xmlns:xsd="http://common.mgt.user.carbon.wso2.org/xsd">
           <soapenv:Header>
           </soapenv:Header>
           <soapenv:Body>
              <ser:deleteUser>
                 <!--Optional:-->
                 <ser:userName>"""+userName+"""</ser:userName>
              </ser:deleteUser>
           </soapenv:Body>
        </soapenv:Envelope>
        """
        return self.handle_request(headers, payload_xml)

    def is_user(self, userName: str):
        self.last_operation = "Is User : "+userName
        headers = {
            'Authorization': 'Basic '+self.authorization,
            'Content-Type': 'text/xml;charset=UTF-8',
            'SOAPAction': 'urn:isExistingUser',
        }
        payload_xml = """
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" 
                          xmlns:ser="http://service.ws.um.carbon.wso2.org" 
                          xmlns:xsd="http://common.mgt.user.carbon.wso2.org/xsd">
           <soapenv:Header>
           </soapenv:Header>
           <soapenv:Body>
              <ser:isExistingUser>
                 <!--Optional:-->
                 <ser:userName>"""+userName+"""</ser:userName>
              </ser:isExistingUser>
           </soapenv:Body>
        </soapenv:Envelope>
        """
        return self.handle_request(headers, payload_xml)

    def get_user_role(self, userName: str):
        self.last_operation = "User Roles : "+userName
        headers = {
            'Authorization': 'Basic '+self.authorization,
            'Content-Type': 'text/xml;charset=UTF-8',
            'SOAPAction': 'urn:getRoleListOfUser',
        }
        payload_xml = """
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" 
                          xmlns:ser="http://service.ws.um.carbon.wso2.org" 
                          xmlns:xsd="http://common.mgt.user.carbon.wso2.org/xsd">
           <soapenv:Header>
           </soapenv:Header>
           <soapenv:Body>
              <ser:getRoleListOfUser>
                 <!--Optional:-->
                 <ser:userName>"""+userName+"""</ser:userName>
              </ser:getRoleListOfUser>
           </soapenv:Body>
        </soapenv:Envelope>
        """
        return self.handle_request(headers, payload_xml)

    def handle_request(self, headers, payload):
        self.last_operation_code     = 200
        self.last_operation_error    = ""
        self.last_operation_details  = ""
        self.last_operation_response = ""
        self.last_operation_headers = headers
        self.last_operation_payload = payload
        self.last_operation_text    = ""

        logger.debug(str(headers))
        logger.debug(str(payload))
        logger.debug(str(json.dumps(xmltodict.parse(payload, process_namespaces=False), indent=2)))

        url = WSO2_SERVER + '/services/RemoteUserStoreManagerService.RemoteUserStoreManagerServiceHttpsSoap11Endpoint'
        response = requests.post(url, headers=headers, data=payload, verify=False)
        self.last_operation_code = response.status_code

        logger.debug(str(response))
        logger.debug(str(response.status_code))
        logger.debug(str(response.text))

        dict_resp = {}
        if (response.text) :
            self.last_operation_text     = response.text
            dict_resp = xmltodict.parse(response.text, process_namespaces=False)
            self.last_operation_response = str(json.dumps(dict_resp["soapenv:Envelope"]["soapenv:Body"], indent=2))

        if (response.status_code == 500):
            self.last_operation_error    = dict_resp["soapenv:Envelope"]["soapenv:Body"]["soapenv:Fault"]["faultcode"]
            self.last_operation_details  = dict_resp["soapenv:Envelope"]["soapenv:Body"]["soapenv:Fault"]["detail"]
            self.last_operation_response = dict_resp["soapenv:Envelope"]["soapenv:Body"]["soapenv:Fault"]["faultstring"]
            return self.last_operation_response

        if (response.status_code == 200):
            if ("ns:listUsersResponse" in dict_resp["soapenv:Envelope"]["soapenv:Body"]):
                self.last_operation_response = str(dict_resp["soapenv:Envelope"]["soapenv:Body"]["ns:listUsersResponse"]["ns:return"])
            if ("ns:isExistingUserResponse" in dict_resp["soapenv:Envelope"]["soapenv:Body"]):
                self.last_operation_response = str(dict_resp["soapenv:Envelope"]["soapenv:Body"]["ns:isExistingUserResponse"]["ns:return"])
            if ("ns:getRoleListOfUserResponse" in dict_resp["soapenv:Envelope"]["soapenv:Body"]):
                self.last_operation_response = str(dict_resp["soapenv:Envelope"]["soapenv:Body"]["ns:getRoleListOfUserResponse"]["ns:return"])
            # print(self.last_operation_response)
            return self.last_operation_response

        if (response.status_code == 202):
            # print("202 : The request has been accepted for processing.")
            return "Success 202"


class RestHandler:

    def __init__(self, server=WSO2_SERVER):
        self.service       = "admin"
        self.client_Id     = ""
        self.client_Secret = ""
        self.client_Token  = ""
        self.access_Token  = ""
        self.refresh_Token = ""
        self.token_Type    = ""
        self.server        = server
        self.op            = "GET"
        self.rest_headers  = ""
        self.rest_request  = ""
        self.rest_payload  = ""
        self.rest_response = ""
        self.s_data  = None  # Send Dict
        self.s_text  = None  # Send Text
        self.r_code  = 0     # Returned Code
        self.r_data  = None  # Returned JSON / Dict
        self.r_text  = None  # Returned Text
        self.d_data  = None  # Returned SuperDict
        self.logs    = ""    # Logs so far
        self.timestamp = datetime.datetime.now()
        self.latency = 0
        self.authentified = False

    def start(self):
        self.timestamp = datetime.datetime.now()

    def completed(self):
        diff = datetime.datetime.now() - self.timestamp
        self.latency = round(diff.seconds * 1000 + diff.microseconds / 1000, 0)
        self.logs = self.logs + self.txt()
        logger.info(self.txt())

    def handle(self, request : str, op : str = None, data=None, headers=None):
        self.start()
        self.op = op.upper() if (op) else self.op.upper()
        if (not (self.op in ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])):
            self.r_text = "Invalid REST Operation : " + self.op
            self.r_code = 400
            self.completed()
            return None
        if (self.server.startswith("http:")) or (self.server.startswith("https:")):
            self.rest_request = self.server + '/' + request
        else:
            self.rest_request = WSO2_SERVER + '/' + request
        logger.info("REST "+op+" : " + str(self.rest_request))
        self.s_data = None
        self.s_text = None
        self.r_data = None
        self.d_data = None
        self.r_text = None
        if (data):
            if (isinstance(data, dict)):         self.s_data = data
            if (isinstance(data, ut.SuperDict)): self.s_data = data.getAsData()
            if (isinstance(data, str)):          self.s_text = data
        if (self.s_data):
            self.s_text = json.dumps(self.s_data)
        try:
            if (self.s_data):
                if (self.op == "GET")    : self.rest_response = requests.get(self.rest_request,     json=self.s_data, headers=headers, verify=False)
                if (self.op == "DELETE") : self.rest_response = requests.delete(self.rest_request,  json=self.s_data, headers=headers, verify=False)
                if (self.op == "OPTIONS"): self.rest_response = requests.options(self.rest_request, json=self.s_data, headers=headers, verify=False)
                if (self.op == "POST")   : self.rest_response = requests.post(self.rest_request,    json=self.s_data, headers=headers, verify=False)
                if (self.op == "PUT")    : self.rest_response = requests.put(self.rest_request,     json=self.s_data, headers=headers, verify=False)
                if (self.op == "PATCH")  : self.rest_response = requests.patch(self.rest_request,   json=self.s_data, headers=headers, verify=False)
            else:
                if (self.op == "GET")    : self.rest_response = requests.get(self.rest_request,     data=self.s_text, headers=headers, verify=False)
                if (self.op == "DELETE") : self.rest_response = requests.delete(self.rest_request,  data=self.s_text, headers=headers, verify=False)
                if (self.op == "OPTIONS"): self.rest_response = requests.options(self.rest_request, data=self.s_text, headers=headers, verify=False)
                if (self.op == "POST")   : self.rest_response = requests.post(self.rest_request,    data=self.s_text, headers=headers, verify=False)
                if (self.op == "PUT")    : self.rest_response = requests.put(self.rest_request,     data=self.s_text, headers=headers, verify=False)
                if (self.op == "PATCH")  : self.rest_response = requests.patch(self.rest_request,   data=self.s_text, headers=headers, verify=False)
        except Exception as ex:
            logger.exception("Exception REST Operation : " + self.op)
            self.r_code = 400
            self.r_text = str(ex).replace("\\n", "\n")
            self.completed()
            return None
        self.r_code   = self.rest_response.status_code
        self.r_text   = self.rest_response.text.replace("\\n", "\n")
        try:
            self.r_data   = ut.checkJsonContent(self.r_text)
            if (isinstance(self.r_data, dict)):
                self.d_data   = ut.SuperDict(self.r_data)
                self.d_data.clean()
        except:
            self.r_data = None
            self.d_data = None
        self.completed()
        if (self.rest_response.status_code != 200):
            # self.raiseError()
            return self.r_text
        return self.r_text

    def getLogs(self, reset=False):
        the_logs = self.logs
        if (reset):
            self.logs = ""
        return the_logs

    def txt(self):
        txt = "\n> " + self.op + " " + self.rest_request+"\n"
        if (self.s_text):
            txt = txt + "> "+str(self.op)+"\n" + str(self.s_text) + "\n"
        if (self.isError()):
            txt = txt + "< Error : " + str(self.r_code) + " (" + str(self.latency) + ")\n" + ut.textToJson(self.r_text) if (self.r_text) else "" + "\n"
        elif (self.r_text):
            txt = txt + "< OK : "    + str(self.r_code) + " (" + str(self.latency) + ")\n" + ut.textToJson(self.r_text) + "\n"
        return txt+"\n---"

    def summary(self) -> str:
        return "(" + str(self.latency)+") " + str(self.r_code) + " - " + self.op + " " + self.rest_request

    def getURL(self):
        return self.rest_request

    def isError(self) -> bool:
        return (self._getError() != None)

    def _getError(self) -> Union[str, None]:
        if (self.r_code > 299) :
            if (self.d_data and self.d_data.has("code"))   : return str(self.d_data["code"])   + " : " + str(self.d_data["message"])
            if (self.d_data and self.d_data.has("status")) : return str(self.d_data["status"]) + " - " + str(self.d_data["cause"]) + " : " + str(self.d_data["detail"])
            return str(self.r_code)
        return None

    def raiseError(self):
        if (self.r_code > 299):
            raise LookupError(self.r_text)

    def getError(self):
        return self.r_text

    def getContent(self):
        return self.r_text

    def getSuperDict(self):
        return self.d_data

    def hasData(self, code=200):
        if (self.r_code == code) and (self.d_data) :
            return self.d_data
        return None

    def getData(self): return self.r_data

    def get(self, request: str, data=None): return self.handle(request, "GET", data)

    def post(self, request: str, data=None): return self.handle(request, "POST", data)

    def put(self, request: str, data=None): return self.handle(request, "PUT", data)

    def delete(self, request: str, data=None): return self.handle(request, "DELETE", data)

    def patch(self, request: str, data=None): return self.handle(request, "PATCH", data)

    def options(self, request: str, data=None): return self.handle(request, "OPTIONS", data)

    def headers(self, content_type="json", files=None):
        if ((files) or (content_type == "files")):
            return {
                    'Authorization': 'Bearer '     + self.access_Token
            }
        return {
                'Authorization': 'Bearer '     + self.access_Token,
                'Content-Type': 'application/' + content_type
        }

    def url(self, endpoint : str = "apis", entry : str = None, service : str = "admin"):
        if (service == "applications") or (service == "userprofiles"):
            return AEPCTL_Configuration.get("USERS_SERVER") + "/nef-application-user-profile-service/22-03/" + "datastore" + "/" + re.sub("^/", "", endpoint) + ("/" + entry if (entry) else "")
        if (service == "datastore") or (service == "catalog"):
            return AEPCTL_Configuration.get("CATALOG_SERVER") + "/nef-services-catalog-service/22-03/" + "datastore" + "/" + re.sub("^/", "", endpoint) + ("/" + entry if (entry) else "")
        if (service == "subscription"):
            return self.server + "/nef-api-subsciption-service/22-03/" + re.sub("^/", "", endpoint) + ("/" + entry if (entry) else "")
        return self.server + "/api/am/"+service+"/v2/" + re.sub("^/", "", endpoint) + ("/" + entry if (entry) else "")

    def authentify(self):
        if (self.authentified) : return

        try:
            headers = {
                'Authorization' : 'Basic YWRtaW46YWRtaW4=',
                'Content-Type'  : 'application/json',
            }
            data = {
                  "callbackUrl" : "www.google.lk",
                  "clientName"  : "rest_api_publisher",
                  "owner"       : "admin",
                  "grantType"   : "client_credentials password refresh_token",
                  "saasApp"     : True
                  }

            url = WSO2_SERVER + '/client-registration/v0.17/register'
            response = requests.post(url, headers=headers, data=json.dumps(data), verify=False)
            dict_response = json.loads(response.text)
            # print(str(json.dumps(dict_response, indent=2)))
            self.client_Id = dict_response["clientId"]
            self.client_Secret = dict_response["clientSecret"]
            self.client_Token  = base64.b64encode(str(self.client_Id+":"+self.client_Secret).encode('ascii'))
            # print(str(self.client_Token.decode("utf-8")))

            headers = {
                'Authorization': 'Basic '+str(self.client_Token.decode("utf-8")),
                'Content-Type': 'application/x-www-form-urlencoded'
            }

            data = 'grant_type=password&username=admin&password=admin&scope=apim:api_view apim:api_create apim:api_publish apim:subscribe apim:app_manage apim:api_key apim:admin apim:tier_view apim:tier_manage'

            url = WSO2_SERVER + '/oauth2/token'
            response = requests.post(url, headers=headers, data=data, verify=False)
            dict_response = json.loads(response.text)
            # print(str(json.dumps(dict_response, indent=2)))
            self.access_Token   = str(dict_response["access_token"])
            self.refresh_Token  = str(dict_response["refresh_token"])
            self.token_Type     = str(dict_response["token_type"])
            self.authentified   = True
        except Exception as ex:
            logger.exception("Exception AUTH Operation : " + self.op)
            self.r_code = 400
            self.r_text = str(ex).replace("\\n", "\n")
            self.completed()
            raise ex

    def handle_request(self, operation : str = "get", endpoint : str = "apis", entry : str = None, payload=None, files=None, service : str = None) -> Union[str, None]:
        try:
            if (not self.authentified):
                self.authentify()
        except Exception as ex:
            logger.exception("Exception AUTH Operation : " + self.op)
            self.r_code = 400
            self.r_text = str(ex).replace("\\n", "\n")
            self.completed()
            return None
        self.r_code     = 200
        self.rest_headers = ""
        self.rest_payload = payload
        if (not service) : service = self.service

        logger.debug(str(endpoint))
        logger.debug(str(payload))

        self.start()
        self.op = operation.upper() if (operation) else self.op.upper()
        if (not (self.op in ["GET", "LIST", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])):
            self.r_text = "Invalid REST Operation : " + self.op
            self.r_code = 400
            self.completed()
            return None
        self.s_data = None
        self.s_text = None
        self.r_data = None
        self.d_data = None
        self.r_text = None
        if (payload):
            if (isinstance(payload, dict)):         self.s_data = payload
            if (isinstance(payload, ut.SuperDict)): self.s_data = payload.getAsData()
            if (isinstance(payload, str)):          self.s_text = payload
        if (self.s_data):
            self.s_text = json.dumps(self.s_data)

        self.rest_response = None
        try:
            self.rest_headers = self.headers(files=files)
            if (operation.upper() == "GET"):
                self.rest_request = self.url(endpoint, entry, service=service)
                logger.info("REST " + self.op + " : " + self.rest_request)
                self.rest_response = requests.get(self.rest_request,    headers=self.rest_headers, data=payload, files=files, verify=False)
            elif (operation.upper() == "LIST"):
                self.rest_request = self.url(endpoint, service=service)
                logger.info("REST " + self.op + " : " + self.rest_request)
                self.rest_response = requests.get(self.rest_request,    headers=self.rest_headers, data=payload, files=files, verify=False)
            elif (operation.upper() == "POST"):
                self.rest_request = self.url(endpoint, service=service)
                logger.info("REST " + self.op + " : " + self.rest_request)
                self.rest_response = requests.post(self.rest_request,   headers=self.rest_headers, data=payload, files=files, verify=False)
            elif (operation.upper() == "DELETE"):
                self.rest_request = self.url(endpoint, entry, service=service)
                logger.info("REST " + self.op + " : " + self.rest_request)
                self.rest_response = requests.delete(self.rest_request, headers=self.rest_headers, data=payload, files=files, verify=False)
            elif (operation.upper() == "PUT"):
                self.rest_request = self.url(endpoint, entry, service=service)
                logger.info("REST " + self.op + " : " + self.rest_request)
                self.rest_response = requests.put(self.rest_request,    headers=self.rest_headers, data=payload, files=files, verify=False)
        except Exception as ex:
            logger.exception("Exception REST Operation : " + self.op)
            self.r_code = 400
            self.r_text = str(ex).replace("\\n", "\n")
            self.completed()
            return None
        logger.debug(str(self.rest_response))
        self.r_code   = self.rest_response.status_code
        self.r_text   = self.rest_response.text.replace("\\n", "\n")
        self.r_text   = self.rest_response.text.replace("©", "(c)")
        if (self.r_text.startswith("[")) :
            self.r_text = re.sub("^\[", "{ \"list\" : [", self.r_text)
            self.r_text = re.sub("\]$", "]}", self.r_text)

        try:
            self.r_data   = ut.checkJsonContent(self.r_text)
            if (isinstance(self.r_data, dict)):
                self.d_data   = ut.SuperDict(self.r_data)
                self.d_data.clean()
        except:
            self.r_data = None
            self.d_data = None

        if (self.rest_response.text) :
            self.r_text = self.rest_response.text
        else :
            self.r_text = str(self.rest_response.status_code)
        self.completed()
        return self.r_text


class Wso2ApiManager(RestHandler):

    def __init__(self, server=WSO2_SERVER):
        super().__init__(server)

    # application / custom / advanced / deny-policies / mediation / subscription
    @staticmethod
    def policy_type(policyType : str = "advanced"):
        if   (policyType == "application"):   return "throttling/policies/application"
        elif (policyType == "custom"):        return "throttling/policies/custom"
        elif (policyType == "advanced"):      return "throttling/policies/advanced"
        elif (policyType == "deny-policies"): return "throttling/policies/deny-policies"
        elif (policyType == "subscription"):  return "throttling/policies/subscription"
        elif (policyType == "mediation"):     return "policies/mediation"

    def policy_create(self, policy : str, policyType : str = "advanced"):
        self.handle_request("POST", self.policy_type(policyType), payload=policy)
        if (self.r_code == 201) and (self.r_text) :
            return json.loads(self.r_text)
        return None

    def policy_list(self, policyType : str = "advanced"):
        self.handle_request("LIST", self.policy_type(policyType))
        if (self.r_code == 200) and (self.r_text) :
            return json.loads(self.r_text)
        return None

    def policy_get(self, policy_id, policyType : str = "advanced"):
        self.handle_request("GET", self.policy_type(policyType), entry=policy_id)
        if (self.r_code == 200) and (self.r_text) :
            return json.loads(self.r_text)
        return None

    def policy_delete(self, policy_id, policyType : str = "advanced"):
        self.handle_request("DELETE", self.policy_type(policyType), entry=policy_id)
        if (self.r_code == 200) and (self.r_text) :
            return json.loads(self.r_text)
        return None

    def category_create(self, category : str):
        self.handle_request("POST", "api-categories", payload=category)
        if (self.r_code == 201) and (self.r_text) :
            return json.loads(self.r_text)
        return None

    def category_list(self, service="admin"):
        self.handle_request("LIST", "api-categories", service=service)
        if (self.r_code == 200) and (self.r_text) :
            return json.loads(self.r_text)
        return None

    def category_get(self, category_id):
        self.handle_request("GET", "api-categories", entry=category_id)
        if (self.r_code == 200) and (self.r_text) :
            return json.loads(self.r_text)
        return None

    def category_delete(self, category_id):
        self.handle_request("DELETE", "api-categories", entry=category_id)
        if (self.r_code == 200) and (self.r_text) :
            return json.loads(self.r_text)
        return None

    def api_list(self, names : bool = False, names_versions : bool = False, ids : bool = False, versions: bool = False):
        self.handle_request("LIST", "apis?limit=2000", service="publisher")
        if (self.hasData()) :
            if (names) :
                names = []
                for api in self.d_data.getAsData()["list"] :
                    names.append(api["name"])
                return names
            if (names_versions) :
                names_versions = []
                for api in self.d_data.getAsData()["list"] :
                    names_versions.append(api["name"]+"/"+api["version"])
                return names_versions
            if (versions) :
                versions = []
                for api in self.d_data.getAsData()["list"] :
                    versions.append({"name" : api["name"] , "version" : api["version"], "id" : api["id"]})
                return versions
            if (ids) :
                ids = []
                for api in self.d_data.getAsData()["list"] :
                    ids.append(api["id"])
                return ids
            return json.loads(self.r_text)
        return None

    def api_id_by_name(self, name : str, version: str = None) -> Union[str, None]:
        if ("/" in name):
            version = re.sub(".*\/", "", name)
            name    = re.sub("\/.*", "", name)
        else :
            if (not version) : return name
        self.handle_request("LIST", "apis?limit=2000", service="publisher")
        if (self.r_code == 200) and (self.r_text) :
            for api in self.d_data.getAsData()["list"] :
                if ((api["name"] == name) and (api["version"] == version)):
                    return api["id"]
        return None

    def api_create(self, api : str, swagger_file : str = None, publish : bool = False) -> Union[str, None]:
        self.handle_request("POST", "apis", payload=api, service="publisher")
        if self.isError() : return None
        if (not swagger_file):
            if (self.r_code == 201) and (self.r_text) :
                return json.loads(self.r_text)
            return None
        r_val  = json.loads(self.r_text)
        api_id = r_val["id"]
        files = {'file': open(swagger_file, 'rb')}
        self.handle_request("PUT", "apis/"+api_id+"/swagger", files=files, service="publisher")
        if (publish):
            self.api_publish(api_id)
        return r_val

    def api_publish(self, api_id):
        self.handle_request("POST", "apis/change-lifecycle?apiId="+api_id+"&action=Publish", service="publisher")
        if (self.r_code == 200) and (self.r_text) :
            return json.loads(self.r_text)
        return None

    def api_get(self, api_id):
        self.handle_request("GET", "apis", entry=api_id, service="publisher")
        if (self.r_code == 200) and (self.r_text) :
            return json.loads(self.r_text)
        return None

    def api_delete(self, api_id : str = None, name : str = None, version: str = None):
        if (api_id) :
            self.handle_request("DELETE", "apis", entry=api_id, service="publisher")
            if (self.r_code == 200) and (self.r_text) :
                return json.loads(self.r_text)
            return None
        elif ((name) and (version)) :
            return self.api_delete(api_id=self.api_id_by_name(name, version))
        return None

    def api_details(self, api_id : str):
        if (not api_id) : return "No API idName specified"
        if (api_id.upper() in ["", "ALL"]) : return "Invalid API idName : " + api_id
        api_id = self.api_id_by_name(api_id)
        api_details = ut.SuperDict()
        self.handle_request("GET", "apis", entry=api_id, service="publisher")
        api_details["api"] = self.d_data
        self.handle_request("GET", "apis", entry=api_id+"/swagger", service="publisher")
        api_details["swagger"] = self.d_data
        self.handle_request("GET", "apis", entry=api_id+"/thumbnail", service="publisher")
        api_details["thumbnail"] = self.d_data
        self.handle_request("GET", "apis", entry=api_id+"/subscription-policies", service="publisher")
        api_details["subscription-policies"] = self.d_data
        self.handle_request("GET", "apis", entry=api_id+"/resource-paths", service="publisher")
        api_details["resource-paths"] = self.d_data
        self.handle_request("GET", "apis", entry=api_id+"/asyncapi", service="publisher")
        api_details["asyncapi"] = self.d_data
        self.handle_request("GET", "apis", entry=api_id+"/lifecycle-history", service="publisher")
        api_details["lifecycle-history"] = self.d_data
        self.handle_request("GET", "apis", entry=api_id+"/lifecycle-state", service="publisher")
        api_details["lifecycle-state"] = self.d_data
        self.handle_request("GET", "apis", entry=api_id+"/revisions?query=deployed:true", service="publisher")

        self.handle_request("GET", "apis", entry=api_id+"/deployments", service="publisher")
        api_details["deployments"] = self.d_data
        self.handle_request("GET", "apis", entry=api_id+"/comments", service="publisher")
        api_details["comments"] = self.d_data
        self.handle_request("GET", "apis", entry=api_id+"/monetize", service="publisher")
        api_details["monetize"] = self.d_data
        self.handle_request("GET", "apis", entry=api_id+"/documents", service="publisher")
        api_details["documents"] = self.d_data
        self.handle_request("GET", "apis", entry=api_id+"/mediation-policies", service="publisher")
        api_details["mediation-policies"] = self.d_data
        self.handle_request("GET", "apis", entry=api_id+"/auditapi", service="publisher")
        api_details["auditapi"] = self.d_data
        self.handle_request("GET", "apis", entry=api_id+"/external-stores", service="publisher")
        api_details["external-stores"] = self.d_data
        self.handle_request("GET", "apis", entry=api_id+"/client-certificates", service="publisher")  # ?alias=wso2carbon
        api_details["client-certificates"] = self.d_data
        self.handle_request("GET", "subscriptions?"+api_id, service="publisher")
        api_details["external-stores"] = self.d_data
        return api_details

    def product_create(self, api : str):
        self.handle_request("POST", "api-products", payload=api, service="publisher")
        if (self.r_code == 201) and (self.r_text) :
            return json.loads(self.r_text)
        return None

    def product_list(self):
        self.handle_request("LIST", "api-products", service="publisher")
        if (self.r_code == 200) and (self.r_text) :
            return json.loads(self.r_text)
        return None

    def product_get(self, product_id):
        self.handle_request("GET", "api-products", entry=product_id, service="publisher")
        if (self.r_code == 200) and (self.r_text) :
            return json.loads(self.r_text)
        return None

    def product_delete(self, product_id):
        self.handle_request("DELETE", "api-products", entry=product_id, service="publisher")
        if (self.r_code == 200) and (self.r_text) :
            return json.loads(self.r_text)
        return None

    def product_details(self, product_id):
        product_details = ut.SuperDict()
        self.handle_request("GET", "api-products", entry=product_id, service="publisher")
        product_details["api"] = self.d_data if (self.d_data) else {}
        self.handle_request("GET", "apis", entry=product_id+"/swagger", service="publisher")
        product_details["swagger"] = self.d_data if (self.d_data) else {}
        self.handle_request("GET", "apis", entry=product_id+"/thumbnail", service="publisher")
        product_details["thumbnail"] = self.d_data if (self.d_data) else {}
        self.handle_request("GET", "apis", entry=product_id+"/documents", service="publisher")
        product_details["documents"] = self.d_data if (self.d_data) else {}
        self.handle_request("GET", "apis", entry=product_id+"/revisions?query=deployed:true", service="publisher")
        product_details["revisions"] = self.d_data if (self.d_data) else {}

        print(str(product_details))
        return product_details

    def settings_get(self):
        settings = ut.SuperDict()
        self.handle_request("GET", "settings", service="admin")
        settings["settings"] = self.d_data if (self.d_data) else {}
        self.handle_request("GET", "alert-types", service="admin")
        settings["alert-types"] = self.d_data if (self.d_data) else {}
        self.handle_request("GET", "key-managers", service="admin")
        settings["key-managers"] = self.d_data if (self.d_data) else {}
        self.handle_request("GET", "environments", service="admin")
        settings["environments"] = self.d_data if (self.d_data) else {}
        self.handle_request("GET", "bot-detection-data", service="admin")
        settings["bot-detection-data"] = self.d_data if (self.d_data) else {}
        self.handle_request("GET", "api-categories", service="admin")
        settings["api-categories"] = self.d_data if (self.d_data) else {}

        # Policy Types : application / custom / advanced / deny-policies / mediation / subscription
        self.handle_request("GET", "throttling/policies/application", service="admin")
        settings["throttling/policies/application"] = self.d_data if (self.d_data) else {}
        self.handle_request("GET", "throttling/policies/custom", service="admin")
        settings["throttling/policies/custom"] = self.d_data if (self.d_data) else {}
        self.handle_request("GET", "throttling/policies/advanced", service="admin")
        settings["throttling/policies/advanced"] = self.d_data if (self.d_data) else {}
        self.handle_request("GET", "throttling/policies/deny-policies", service="admin")
        settings["throttling/policies/deny-policies"] = self.d_data if (self.d_data) else {}
        self.handle_request("GET", "policies/mediation", service="admin")
        settings["policies/mediation"] = self.d_data if (self.d_data) else {}
        self.handle_request("GET", "throttling/policies/subscription", service="admin")
        settings["throttling/policies/subscription"] = self.d_data if (self.d_data) else {}

        self.handle_request("LIST", "apis", service="publisher")
        settings["publisher/apis"] = self.d_data if (self.d_data) else {}
        self.handle_request("LIST", "tenants?state=active", service="publisher")
        settings["publisher/tenants"] = self.d_data if (self.d_data) else {}
        self.handle_request("LIST", "subscriptions", service="publisher")
        settings["publisher/subscriptions"] = self.d_data if (self.d_data) else {}
        self.handle_request("LIST", "mediation-policies", service="publisher")
        settings["publisher/mediation-policies"] = self.d_data if (self.d_data) else {}
        self.handle_request("LIST", "api-products", service="publisher")
        settings["publisher/api-products"] = self.d_data if (self.d_data) else {}
        self.handle_request("LIST", "settings", service="publisher")
        settings["publisher/settings"] = self.d_data if (self.d_data) else {}

        return settings


class Wso2ApiDevManager(RestHandler):

    def application_create(self, application : str):
        self.handle_request("POST", "applications", payload=application, service="devportal")
        if (self.r_code == 201) and (self.r_text) :
            return json.loads(self.r_text)
        return None

    def application_list(self, names : bool = True):
        self.handle_request("LIST", "applications?limit=2000", service="devportal")
        if (self.r_code == 200) and (self.r_text) :
            if (names) :
                names = []
                for app in self.d_data.getAsData()["list"] :
                    names.append(app["name"])
                return names
            return json.loads(self.r_text)
        return None

    def application_get(self, app_id):
        self.handle_request("GET", "applications", entry=app_id, service="devportal")
        if (self.r_code == 200) and (self.r_text) :
            return json.loads(self.r_text)
        return None

    def application_delete(self, app_id: str = None, name: str = None):
        if (app_id) :
            self.handle_request("DELETE", "applications", entry=app_id, service="devportal")
            if (self.r_code == 200) and (self.r_text) :
                return json.loads(self.r_text)
            return None
        elif (name) :
            return self.application_delete(app_id=self.application_id_by_name(name))
        return None

    def application_details(self, app_id):
        app_details = ut.SuperDict()
        self.handle_request("GET", "applications", entry=app_id, service="devportal")
        app_details["api"] = self.d_data
        self.handle_request("GET", "applications", entry=app_id+"/swagger", service="devportal")
        app_details["swagger"] = self.d_data
        return app_details

    def application_id_by_name(self, name : str) -> Union[str, None]:
        self.handle_request("LIST", "applications?limit=2000", service="devportal")
        if (self.r_code == 200) and (self.r_text) :
            for api in self.d_data.getAsData()["list"] :
                if (api["name"] == name):
                    return api["applicationId"]
        return None

    def application_get_keys(self, app_id : str = None, app_name : str = None):
        if (app_name):
            app_id = self.application_id_by_name(app_name)
        if (not app_id) : return None
        self.handle_request("GET", "applications/"+app_id+"/oauth-keys", service="devportal")
        return self.getData()

    def application_generate_keys(self, app_id : str = None, app_name : str = None):
        if (app_name):
            app_id = self.application_id_by_name(app_name)
        if (not app_id) : return None
        generate_keys = """
                {
                    "keyType": "PRODUCTION",
                    "keyManager": "Resident Key Manager",
                    "grantTypesToBeSupported": [
                        "password",
                        "client_credentials"
                    ],
                    "callbackUrl": "http://sample.com/callback/url",
                    "scopes": [
                        "am_application_scope",
                        "default"
                    ],
                    "validityTime": "3600",
                    "additionalProperties": {}
                }
        """
        self.handle_request("POST", "applications/"+app_id+"/generate-keys", payload=generate_keys, service="devportal")
        return self.getData()

    def subscription_create(self, subscription : str):
        self.handle_request("POST", "subscriptions", payload=subscription, service="devportal")
        if (self.r_code == 201) and (self.r_text) :
            return json.loads(self.r_text)
        return None

    def subscription_list(self, applicationId: str = None, apiId: str = None):
        suffix = ""
        if (applicationId) : suffix = suffix + "&applicationId="+applicationId
        if (apiId)         : suffix = suffix + "&apiId="+apiId
        self.handle_request("LIST", "subscriptions?limit=2000"+suffix, service="devportal")
        if (self.r_code == 200) and (self.r_text) :
            return json.loads(self.r_text)
        return None

    def subscription_get(self, subs_id):
        self.handle_request("GET", "subscriptions", entry=subs_id, service="devportal")
        if (self.r_code == 200) and (self.r_text) :
            return json.loads(self.r_text)
        return None

    def subscription_delete(self, subs_id: str = None, name: str = None):
        if (subs_id) :
            self.handle_request("DELETE", "subscriptions", entry=subs_id, service="devportal")
            if (self.r_code == 200) and (self.r_text) :
                return json.loads(self.r_text)
            return None
        elif (name) :
            return self.application_delete(app_id=self.application_id_by_name(name))
        return None

    def subscription_details(self, subs_id):
        app_details = ut.SuperDict()
        self.handle_request("GET", "subscriptions", entry=subs_id, service="devportal")
        app_details["subscription"] = self.d_data
        return app_details

    def subscription_id(self, app_id : str, api_id : str) -> Union[str, None]:
        self.subscription_list(apiId=api_id, applicationId=app_id)
        if (not self.hasData()) : return None
        for subs in self.d_data.getAsData()["list"]:
            if ((subs["applicationId"] == app_id) and (subs["apiId"] == api_id)):
                return subs["subscriptionId"]
        return None

    def subscribe(self, app_id : str = None, app_name : str = None, api_id : str = None, api_name : str = None, api_version : str = None, policy : str = "Unlimited"):
        if (app_name) :
            app_id = self.application_id_by_name(app_name)
        if (not app_id):
            return None
        if (api_name) :
            api_id = self.api_id_by_name(name=api_name, version=api_version)
        if (not api_id):
            return None
        subscription = {"applicationId": app_id, "apiId": api_id, "throttlingPolicy": policy}
        return self.subscription_create(json.dumps(subscription))

    def unsubscribe(self, app_id : str = None, app_name : str = None, api_id : str = None, api_name : str = None, api_version : str = None):
        if (app_name) :
            app_id = self.application_id_by_name(app_name)
        if (not app_id): return None
        if (api_name) :
            api_id = self.api_id_by_name(name=api_name, version=api_version)
        if (not api_id): return None
        subscription_id = self.subscription_id(app_id=app_id, api_id=api_id)
        if (not subscription_id) : return None
        return self.subscription_delete(subscription_id)

    def settings_get(self):
        settings = ut.SuperDict()
        self.handle_request("GET", "settings", service="devportal")
        settings["settings"] = self.d_data if (self.d_data) else {}
        self.handle_request("GET", "key-managers", service="devportal")
        settings["key-managers"] = self.d_data if (self.d_data) else {}
        self.handle_request("GET", "api-categories", service="devportal")
        settings["api-categories"] = self.d_data if (self.d_data) else {}
        self.handle_request("GET", "tags", service="devportal")
        settings["tags"] = self.d_data if (self.d_data) else {}
        self.handle_request("GET", "sdk-gen/languages", service="devportal")
        settings["sdk-gen-languages"] = self.d_data if (self.d_data) else {}
        self.handle_request("GET", "apis", service="devportal")
        settings["apis"] = self.d_data if (self.d_data) else {}
        self.handle_request("GET", "applications", service="devportal")
        settings["applications"] = self.d_data if (self.d_data) else {}
        self.handle_request("LIST", "tenants?state=active", service="devportal")
        settings["tenants"] = self.d_data if (self.d_data) else {}

        # Policy Types : application / custom / advanced / deny-policies / mediation / subscription
        self.handle_request("GET", "throttling/policies/application", service="devportal")
        settings["throttling/policies/application"] = self.d_data if (self.d_data) else {}

        return settings

###
### DataStore
###


class DataStoreInterface():

    def __init__(self):
        pass

    def create(self, entity=None) -> Union [dict, None]:
        pass

    def error(self) -> Union [str, None]:
        pass

    def list(self, names : bool = False, ids : bool = False, count : bool = False) -> Union [list, None]:
        pass

    def id_by_name(self, name : str) -> str:
        pass

    def name_by_id(self, id : str) -> str:
        pass

    def desc_by_idname(self, idname : str) -> Union[str, None]:
        pass

    def exist(self, entity : str) -> bool:
        pass

    def get(self, entity : str = None , name : str = None, entry_id : str = None) -> Union [dict, None]:
        pass

    def update(self, entity) -> Union [dict, None]:
        pass

    def delete(self, entity : str = None , name : str = None, entry_id : str = None) -> Union [dict, None]:
        pass

    def delete_all(self) -> Union [list, None]:
        pass

    def dump_all(self, filename : str = None, directory : str = BACKUP_DIRECTORY) -> bool:
        pass

    def store_file(self, filename : str = None, directory : str = STORE_DIRECTORY) -> bool:
        pass

    def load_file(self, filename : str = None, directory : str = STORE_DIRECTORY) -> bool:
        pass


class FileDataStore(DataStoreInterface):

    def __init__(self, directory=STORE_DIRECTORY, entity_type="articles", name_att="ArticleName", desc_att="ArticleDesc", id_att="id", service="datastore"):
        super().__init__()
        self.entity_type = entity_type
        self.name_att    = name_att
        self.desc_att    = desc_att
        self.id_att      = id_att
        self.service     = service
        self.cache       = list()
        self.load_file(directory=directory)
        self.errortxt    = None

    def error(self) -> Union [str, None]:
        return self.errortxt

    def create(self, entity=None) -> Union [dict, None]:
        self.errortxt       = None
        if (isinstance(entity, str)) :
            entity = ut.loadDataContent(entity)
            if (not entity):
                self.errortxt = "Invalid Format : "+str(entity)
                return None
        if (not isinstance(entity, dict)) :
            self.errortxt = "Invalid Format : "+str(entity)
            return None
        entity[self.id_att] = ut.uuid()
        self.errortxt = StoreManager.check_schema(entity, self.entity_type)
        if (self.error()):
            return None
        StoreManager.store_back_up(store_type="file")
        self.cache.append(entity)
        self.store_file()
        return entity

    def list(self, names : bool = False, ids : bool = False, count : bool = False) -> Union [list, None, int]:
        self.errortxt       = None
        if (names) :
            names = []
            for entry in self.cache:
                names.append(entry[self.name_att])
            return names
        if (ids) :
            ids = []
            for entry in self.cache:
                ids.append(entry[self.id_att])
            return ids
        if (count) :
            return len(self.cache)
        return self.cache

    def id_by_name(self, name : str) -> Union[str, None]:
        for entry in self.cache:
            if (entry[self.name_att] == name):
                return entry[self.id_att]
        return None

    def name_by_id(self, id : str) -> str:
        for entry in self.cache:
            if (entry[self.id_att] == id):
                return entry[self.name_att]
        return None

    def desc_by_idname(self, idname : str) -> Union[str, None]:
        for entry in self.cache:
            if (entry[self.id_att] == idname):
                return entry[self.desc_att]
            if (entry[self.name_att] == idname):
                return entry[self.desc_att]
        return None

    def exist(self, entity : str) -> bool:
        for entry in self.cache:
            if (entry[self.name_att] == entity): return True
            if (entry[self.id_att] == entity):   return True
        return False

    def get(self, entity : str = None , name : str = None, entry_id : str = None) -> Union [dict, None]:
        self.errortxt = None
        entity_id = None
        if (entity):
            value = entity
            entity_id = self.id_by_name(entity)
            if (not entity_id) : entity_id = entity
        if (name):
            value = name
            entity_id = self.id_by_name(entity)
        if (entry_id):
            value = entry_id
            entity_id = entry_id
        for entry in self.cache:
            if (entry[self.id_att] == entity_id):   return entry
        self.errortxt = "No such entry : " + str(value)
        return None

    def update(self, entity) -> Union [dict, None]:
        self.errortxt = None
        if (isinstance(entity, str)) :
            entity = ut.loadDataContent(entity)
            if (not entity):
                self.errortxt = "Invalid Format : "+str(entity)
                return None
        if (not isinstance(entity, dict)) :
            self.errortxt = "Invalid Format : "+str(entity)
            return None
        entity_id  = entity[self.id_att]
        old_entity = self.delete(entry_id=entity_id)
        new_entity = old_entity | entity
        self.errortxt = StoreManager.check_schema(entity, self.entity_type)
        if (self.error()):
            return None
        StoreManager.store_back_up(store_type="file")
        self.cache.append(new_entity)
        self.store_file()
        return new_entity

    def delete(self, entity : str = None , name : str = None, entry_id : str = None) -> Union [dict, None]:
        self.errortxt = None
        entity_id = None
        if (entity):
            value = entity
            entity_id = self.id_by_name(entity)
            if (not entity_id) : entity_id = entity
        if (name):
            value = name
            entity_id = self.id_by_name(entity)
        if (entry_id):
            value = entry_id
            entity_id = entry_id
        entry = self.get(entry_id=entity_id)
        if (not entry) :
            self.errortxt = "No such entry : " + str(value)
            return None
        StoreManager.store_back_up(store_type="file")
        self.cache.remove(entry)
        self.store_file()
        return entry

    def delete_all(self) -> Union [list, None]:
        StoreManager.store_back_up(store_type="file")
        self.errortxt = None
        deleted = self.cache
        self.cache.clear()
        self.store_file()
        return deleted

    def dump_all(self, filename : str = None, directory : str = BACKUP_DIRECTORY) -> bool:
        self.errortxt = None
        store = dict()
        store["name_att"] = self.name_att
        store["desc_att"] = self.desc_att
        store["service"]  = self.service
        store["entity"]   = self.entity_type
        store["count"]    = len(self.cache)
        store["entries"]  = self.cache
        if (not filename):
            ut.safeCreateDir(directory)
            logger.info("BackUp Dir : " + directory)
            filename = directory + os.sep + self.entity_type + "_dump.json"
        ut.saveJsonFile(store, filename)
        logger.info("Saved : " + filename)
        return True

    def store_file(self, filename : str = None, directory : str = STORE_DIRECTORY) -> bool:
        self.errortxt = None
        store = dict()
        store["name_att"] = self.name_att
        store["desc_att"] = self.desc_att
        store["service"]  = self.service
        store["entity"]   = self.entity_type
        store["count"]    = len(self.cache)
        store["entries"]  = self.cache
        if (not ut.safeDirExist(directory)):
            logger.info("Creating Directory : " + directory)
            ut.safeCreateDir(directory)
        if (not filename):
            filename = directory + os.sep + self.entity_type + "_dump.json"
        logger.info("Saving File  : " + str(filename))
        ut.saveJsonFile(store, filename)
        return True

    def load_file(self, filename : str = None, directory : str = STORE_DIRECTORY) -> bool:
        self.errortxt = None
        if (not ut.safeDirExist(directory)):
            logger.info("Creating Directory : " + directory)
            ut.safeCreateDir(directory)
        if (not filename):
            filename = directory + os.sep + self.entity_type + "_dump.json"
        if (not ut.safeFileExist(filename)):
            logger.info("File not found : " + str(filename))
            logger.info("Creating File  : " + str(filename))
            self.store_file()
        logger.info("Loading File : " + filename)
        data = ut.loadDataFile(filename)
        if (not data):
            logger.info("Invalid Data Format : " + filename)
            return False
        data = StoreManager.check_entry(data)
        self.entity_type = data["entity"]
        self.name_att    = data["name_att"]
        self.desc_att    = data["desc_att"]
        self.service     = data["service"]
        self.cache       = data["entries"]
        logger.info("Loaded File  : " + filename)
        return True

    def load_server(self) -> bool:
        self.errortxt = None
        server = RestDataStore(entity_type=self.entity_type, name_att=self.name_att, desc_att=self.desc_att, id_att=self.id_att, service=self.service)
        self.cache = server.list()
        return True

    def store_server(self) -> bool:
        self.errortxt = None
        server = RestDataStore(entity_type=self.entity_type, name_att=self.name_att, desc_att=self.desc_att, id_att=self.id_att, service=self.service)
        for entry in self.cache:
            server.update(entry)
        return True


class RestDataStore(RestHandler, DataStoreInterface):

    def __init__(self, server=CATALOG_SERVER, entity_type="articles", name_att="ArticleName", desc_att="ArticleDesc", id_att="id", service="datastore"):
        super().__init__(server)
        self.entity_type = entity_type
        self.name_att    = name_att
        self.desc_att    = desc_att
        self.id_att      = id_att
        self.service     = service
        self.errortxt    = None

    def error(self) -> Union [str, None]:
        if (self.errortxt):
            return self.errortxt
        return self._getError()

    def create(self, entity=None) -> Union [dict, None]:
        self.errortxt    = None
        if (isinstance(entity, str))  : entity = json.loads(entity)
        if (not isinstance(entity, dict)) : return None
        if ("id" not in entity) : entity["id"] = "id"
        entity = json.dumps(entity)
        self.errortxt = StoreManager.check_schema(entity, self.entity_type)
        if (self.error()):
            return None
        StoreManager.store_back_up(store_type="rest")
        self.handle_request("POST", self.entity_type, payload=entity, service=self.service)
        return self.hasData()

    def list(self, names : bool = False, ids : bool = False, count : bool = False) -> Union [list, None]:
        self.errortxt    = None
        self.handle_request("LIST", self.entity_type, service=self.service)
        if (self.isError()) : return None
        if (self.hasData() and names) :
            names = []
            for cat in self.d_data.getAsData()["list"]:
                names.append(cat[self.name_att])
            return names
        if (self.hasData() and ids) :
            ids = []
            for cat in self.d_data.getAsData()["list"]:
                ids.append(cat[self.id_att])
            return ids
        if (self.hasData() and count) :
            return len(self.d_data.getAsData()["list"])
        return self.d_data.getAsData()["list"]

    def id_by_name(self, name : str) -> Union[str, None]:
        self.errortxt    = None
        self.handle_request("LIST", self.entity_type, service=self.service)
        if (self.hasData()) :
            for cat in self.d_data.getAsData()["list"] :
                if (cat[self.name_att] == name):
                    return cat[self.id_att]
        return None

    def name_by_id(self, id : str) -> str:
        self.errortxt    = None
        self.handle_request("LIST", self.entity_type, service=self.service)
        if (self.hasData()) :
            for cat in self.d_data.getAsData()["list"] :
                if (cat[self.id_att] == id):
                    return cat[self.name_att]
        return None

    def desc_by_idname(self, idname : str) -> Union[str, None]:
        self.errortxt    = None
        self.handle_request("LIST", self.entity_type, service=self.service)
        if (self.hasData()) :
            for cat in self.d_data.getAsData()["list"] :
                if (cat[self.id_att] == idname):
                    return cat[self.desc_att]
                if (cat[self.name_att] == idname):
                    return cat[self.desc_att]
        return None

    def exist(self, entity : str) -> bool:
        self.errortxt    = None
        self.handle_request("LIST", self.entity_type, service=self.service)
        if (self.hasData()) :
            for cat in self.d_data.getAsData()["list"] :
                if (cat[self.name_att] == entity):
                    return True
                if (cat[self.id_att] == entity):
                    return True
        return False

    def get(self, entity : str = None , name : str = None, entry_id : str = None) -> Union [dict, None]:
        self.errortxt    = None
        if (entity):
            entity_id = self.id_by_name(entity)
            if (not entity_id) : entity_id = entity
        if (name):
            entity_id = self.id_by_name(entity)
        if (entry_id):
            entity_id = entry_id
        self.handle_request("GET", self.entity_type, entry=entity_id, service=self.service)
        return self.hasData()

    def update(self, entity) -> Union [dict, None]:
        self.errortxt    = None
        if (isinstance(entity, dict)) : entity = json.dumps(entity)
        if (not isinstance(entity, str)) : return None
        entity_data = json.loads(entity)
        if (self.id_att in entity_data) :
            entity_id = entity[self.id_att]
        else :
            entity_id = self.id_by_name(entity[self.name_att])
        self.errortxt = StoreManager.check_schema(entity, self.entity_type)
        if (self.error()):
            return None
        StoreManager.store_back_up(store_type="rest")
        self.handle_request("PUT", self.entity_type, entry=entity_id, payload=entity, service=self.service)
        return self.hasData()

    def delete(self, entity : str = None , name : str = None, entry_id : str = None) -> Union [dict, None]:
        self.errortxt    = None
        if (entity):
            entity_id = self.id_by_name(entity)
            if (not entity_id) : entity_id = entity
        if (name):
            entity_id = self.id_by_name(entity)
        if (entry_id):
            entity_id = entry_id
        StoreManager.store_back_up(store_type="rest")
        self.handle_request("DELETE", self.entity_type, entry=entity_id, service=self.service)
        return self.hasData()

    def delete_all(self) -> Union [list, None]:
        self.errortxt    = None
        StoreManager.store_back_up(store_type="rest")
        for entry_id in self.list(ids=True) :
            self.delete(entry_id=entry_id)

    def dump_all(self, filename : str = None, directory : str = BACKUP_DIRECTORY) -> bool:
        self.errortxt    = None
        entries = list()
        entry_list = self.list(ids=True)
        if (entry_list) :
            for entry_id in entry_list :
                entries.append(self.get(entry_id=entry_id).getAsData())
        store = dict()
        store["desc_att"] = self.desc_att
        store["name_att"] = self.name_att
        store["service"]  = self.service
        store["entity"]   = self.entity_type
        store["count"]    = len(entries)
        store["entries"]  = entries
        if (not filename):
            ut.safeCreateDir(directory)
            filename = directory + os.sep + self.entity_type + "_dump.json"
        ut.saveJsonFile(store, filename)
        return True

    def load_file(self) -> bool:
        self.errortxt    = None
        server = FileDataStore(entity_type=self.entity_type, name_att=self.name_att, id_att=self.id_att, desc_att=self.desc_att, service=self.service)
        server.load_file()
        for entry in server.list():
            self.update(entry)
        return True

    def store_file(self) -> bool:
        self.errortxt    = None
        server = FileDataStore(entity_type=self.entity_type, name_att=self.name_att, id_att=self.id_att, desc_att=self.desc_att, service=self.service)
        server.cache = self.list()
        server.store_file()
        return True

###
### Factory Settings
###


class FactoryLoader:

    @staticmethod
    def b64file_handler(entry : dict) -> dict:
        for key in entry:
            val = entry[key]
            if isinstance(val, str) and val.startswith("@b64file:"):
                filename = re.sub("@b64file:", "", val)
                filename = re.sub(":.*$", "", filename)
                entry[key] = "@b64file:" + filename + ":" + ut.to_file_2_b64(filename)
            if isinstance(val, dict):
                entry[key] = FactoryLoader.b64file_handler(val)
        return entry

    @staticmethod
    def factory_loader(filename, delete_all : bool = False):
        if (ut.safeDirExist(filename)):
            # All json Files in directory
            for file in ut.safeListFiles(dir=filename, file_ext=".json", keepExt=True):
                FactoryLoader.factory_loader(file, delete_all)
            return
        # Specific File
        if (not ut.safeFileExist(filename)):
            logger.error("File not found : "  + filename)
            raise Exception("File not found : " + filename)
        data = ut.loadFileData(filename)
        if (not data):
            # Invalid json or yaml
            logger.error("Invalid json or yaml Content : "  + filename)
            raise Exception("Invalid json or yaml Content : " + filename)
        if ("entity" in data) :
            # All Entries to same store
            data     = StoreManager.check_entry(data)
            service  = data["service"]
            entity   = data["entity"]
            name_att = data["name_att"]
            desc_att = data["desc_att"]
            server   = RestDataStore(service=service, name_att=name_att, entity_type=entity, desc_att=desc_att)
            if (delete_all):
                server.delete_all()
            for entry in data["entries"]:
                if ("id" not in entry["entry"]):
                    entry["entry"]["id"] = "id"
                entry["entry"] = FactoryLoader.b64file_handler(entry["entry"])
                created = server.create(entry["entry"])
                logger.info("Entry Created : " + json.dumps(created, indent=2))
        elif ("entries" in data) :
            # Multiples Entries to different stores
            for entry in data["entries"]:
                print(json.dumps(entry, indent=2))
                data = StoreManager.check_entry(data)
                service  = entry["service"]
                entity   = entry["entity"]
                name_att = entry["name_att"]
                desc_att = entry["desc_att"]
                server = RestDataStore(service=service, name_att=name_att, desc_att=desc_att,  entity_type=entity)
                if (delete_all):
                    logger.info("Delete All : " + entity)
                    server.delete_all()
                if ("id" not in entry["entry"]):
                    entry["entry"]["id"] = "id"
                entry["entry"] = FactoryLoader.b64file_handler(entry["entry"])
                created = server.create(entry["entry"])
                logger.info("Entry Created : " + json.dumps(created, indent=2))
            # Include other files
            if ("include" in data):
                for include_file in data["include"]:
                    logger.info("Including File : " + include_file)
                    FactoryLoader.factory_loader(include_file)
        else :
            logger.error("Invalid File Content : "  + filename)
            raise Exception("Invalid File Content : " + filename)
        return data


FileStoreCache = dict()
RestStoreCache = dict()

###
### Data Stores
###


class StoreManager():

    serviceList = ["applications", "userprofiles", "datastore", "catalog", "subscription", "ws02"]

    def __init__(self, storefile=STORES_FILE):
        self.storefile = storefile
        self.store     = None
        self.stored    = None
        self.loadStores()

    def loadStores(self, storefile : str = None):
        if (storefile) : self.storefile = storefile
        self.store = ut.loadDataFile(self.storefile)
        if (not self.store): return None
        self.stored = dict()
        for store in self.store["stores"] :
            self.stored[store["name"]] = store

    def getStore(self, name : str, file : bool = False) -> DataStoreInterface:
        for store_key in self.stored :
            if (self.stored[store_key]["name"].lower() == name.lower()) :  name = store_key
            if (self.stored[store_key]["entity"].lower() == name.lower()): name = store_key
        if (name not in self.stored): return None
        store = self.stored[name]
        if (file):
            if (store["entity"] in FileStoreCache) :
                return FileStoreCache[store["entity"]]
            filestore = FileDataStore(entity_type=store["entity"], name_att=store["name_att"], desc_att=store["desc_att"], service=store["service"])
            filestore.load_file()
            FileStoreCache[store["entity"]] = filestore
            return filestore
        else :
            if (store["entity"] in RestStoreCache) :
                return RestStoreCache[store["entity"]]
            reststore = RestDataStore(entity_type=store["entity"], name_att=store["name_att"], desc_att=store["desc_att"], service=store["service"])
            reststore.authentify()
            RestStoreCache[store["entity"]] = reststore
            return reststore

    @staticmethod
    def list_store_entities(store_file : str = STORES_FILE, lower : bool = False) -> list:
        stores = StoreManager.check_stores(store_file)
        entity_list = list()
        for store in stores["stores"]:
            entity_list.append(store["entity"].lower() if lower else store["entity"])
        return entity_list

    @staticmethod
    def store_get_schema(store_file : str = STORES_FILE, entity : str = None):
        stores = StoreManager.check_stores(store_file)
        for store in stores["stores"]:
            if (entity.lower() == store["entity"].lower()):
                return store["schema"]
        return None

    @staticmethod
    def store_get_service(store_file : str = STORES_FILE, entity : str = None):
        stores = StoreManager.check_stores(store_file)
        for store in stores["stores"]:
            if (entity.lower() == store["entity"].lower()):
                return store["service"]
        return None

    @staticmethod
    def check_stores(store_file : str = STORES_FILE):
        if (not ut.safeFileExist(store_file)):
            logger.error("File not found : "    + store_file)
            raise Exception("File not found : " + store_file)
        stores    = ut.loadFileData(store_file)
        if (not stores):
            logger.error("Invalid json or yaml content : "    + store_file)
            raise Exception("Invalid json or yaml content : " + store_file)
        if (("stores" not in stores)):
            logger.error("No \"stores\" in : " + store_file)
            raise Exception("No \"stores\" in : " + store_file)
        for store in stores["stores"]:
            if (("service" not in store)):
                logger.error("No \"service\" in store : " + store_file)
                raise Exception("No \"service\" in store : " + store_file)
            if (("entity" not in store)):
                logger.error("No \"entity\" in store : " + store_file)
                raise Exception("No \"entity\" in store : " + store_file)
            if (("name_att" not in store)):
                logger.error("No \"name_att\" in store : " + store_file)
                raise Exception("No \"name_att\" in store : " + store_file)
            if (("desc_att" not in store)):
                logger.error("No \"desc_att\" in store : " + store_file)
                raise Exception("No \"desc_att\" in store : " + store_file)
            if (("name" not in store)):
                logger.error("No \"name\" in store : " + store_file)
                raise Exception("No \"name\" in store : " + store_file)
        return stores

    @staticmethod
    def check_entry(entry: dict):
        if (("service" not in entry)):
            logger.error("No \"service\" in entry : " + json.dumps(entry, indent=2))
            raise Exception("No \"service\" in entry : " + json.dumps(entry, indent=2))
        if (entry["service"].lower() not in StoreManager.serviceList):
            logger.error("Unknown \"service\" in entry : " + entry["service"])
            raise Exception("Unknown \"service\" in entry : " + entry["service"])
        if (("entity" not in entry)):
            logger.error("No \"entity\" in entry : " + json.dumps(entry, indent=2))
            raise Exception("No \"entity\" in entry : " + json.dumps(entry, indent=2))
        if (entry["entity"].lower() not in StoreManager.list_store_entities(lower=True)):
            logger.error("Unknown \"entity\" in entry : " + entry["entity"])
            raise Exception("Unknown \"entity\" in entry : " + entry["entity"])
        if (("name_att" not in entry)):
            logger.error("No \"name_att\" in entry : " + json.dumps(entry, indent=2))
            raise Exception("No \"name_att\" in entry : " + json.dumps(entry, indent=2))
        if (("desc_att" not in entry)):
            logger.error("No \"desc_att\" in entry : " + json.dumps(entry, indent=2))
            raise Exception("No \"desc_att\" in entry : " + json.dumps(entry, indent=2))
        if (("entry" not in entry) and ("entries" not in entry)):
            logger.error("No \"entry\" or \"entries\" in entry : " + json.dumps(entry, indent=2))
            raise Exception("No \"entry\" or \"entries\" in entry : " + json.dumps(entry, indent=2))
        return entry

    @staticmethod
    def get_openapi_file(entity: str) -> Union[str, None]:
        openapiFile = None
        service = StoreManager.store_get_service(entity=entity)
        if (not service):
            return None
        schema = StoreManager.store_get_schema(entity=entity)
        if (not schema):
            return None
        if (service in ["catalog", "datastore"]):
            openapiFile = CONFIG_DIRECTORY + os.sep + "NEF_Catalog_DataModel" + os.sep + "NEF_Catalog_DataModel_API.yaml"
        if (service in ["applications", "userprofiles"]):
            openapiFile = CONFIG_DIRECTORY + os.sep + "NEF_ApplicationUserProfile_DataModel" + os.sep + "NEF_ApplicationUserProfile_DataModel_API.yaml"
        return (openapiFile)

    def get_name_att(self, entity: str) -> Union[str, None]:
        entity = re.sub("^.. ", "", str(entity))
        for store in self.stored:
            if (entity.lower() == store.lower()):
                return self.stored[store]["name_att"]
        return None

    def get_id_att(self, entity: str) -> Union[str, None]:
        entity = re.sub("^.. ", "", str(entity))
        for store in self.stored:
            if (entity.lower() == store.lower()):
                return self.stored[store]["id_att"]
        return None

    def get_desc_att(self, entity: str) -> Union[str, None]:
        entity = re.sub("^.. ", "", str(entity))
        for store in self.stored:
            if (entity.lower() == store.lower()):
                return self.stored[store]["desc_att"]

    @staticmethod
    def get_schema_file(entity: str) -> Union[str, None]:
        schemaFile = None
        service = StoreManager.store_get_service(entity=entity)
        if (not service):
            return None
        schema = StoreManager.store_get_schema(entity=entity)
        if (not schema):
            return None
        if (service in ["catalog", "datastore"]):
            schemaFile = CONFIG_DIRECTORY + os.sep + "NEF_Catalog_DataModel" + os.sep + "_Schemas" + os.sep + schema + ".json"
        if (service in ["applications", "userprofiles"]):
            schemaFile = CONFIG_DIRECTORY + os.sep + "NEF_ApplicationUserProfile_DataModel" + os.sep + "_Schemas" + os.sep + schema + ".json"
        return (schemaFile)

    @staticmethod
    def check_schema(entry: dict, entity: str):
        if isinstance(entry, str):
            try :
                entry = json.loads(entry)
            except Exception as err:
                return str(err.message)
        schemaFile = StoreManager.get_schema_file(entity)
        if (not schemaFile):
            return None
        try:
            ut.validateSchema(entry, schemaFile)
            return None
        except Exception as e:
            logger.error("Entity : " + str(entity) + " : \n" + json.dumps(entry, indent=2) + "\n" + str(e.message))
            return str(e.message)

    @staticmethod
    def get_schema(entity: str) -> dict:
        entity = re.sub("^.. ", "", str(entity))
        schemaFile = StoreManager.get_schema_file(entity)
        if (not schemaFile):
            return None
        return ut.loadFileData(schemaFile)

    @staticmethod
    def get_openapi(entity: str) -> dict:
        entity = re.sub("^.. ", "", str(entity))
        openApiFile = StoreManager.get_openapi_file(entity)
        if (not openApiFile):
            return None
        return ut.loadFileData(openApiFile)

    @staticmethod
    def get_description(entity: str, idName : str):
        resource = re.sub("^.. ", "", str(entity))
        service  = re.sub(" .*$", "", str(entity))
        file_service = True if (service.lower() == "fs") else False
        store = StoreManager().getStore(name=resource, file=file_service)
        return store.desc_by_idname(idName)

    @staticmethod
    def get_identifier(entity: str, idName : str):
        resource = re.sub("^.. ", "", str(entity))
        service  = re.sub(" .*$", "", str(entity))
        file_service = True if (service.lower() == "fs") else False
        store = StoreManager().getStore(name=resource, file=file_service)
        return store.id_by_name(idName)

    @staticmethod
    def get_name(entity: str, idName : str):
        resource = re.sub("^.. ", "", str(entity))
        service  = re.sub(" .*$", "", str(entity))
        file_service = True if (service.lower() == "fs") else False
        store = StoreManager().getStore(name=resource, file=file_service)
        return store.name_by_id(idName)

    @staticmethod
    def store_back_up(directory: str = BACKUP_DIRECTORY, store_file: str = STORES_FILE, store_type: str = "rest", resource : str = "", pstore : str = None ):
        lresource = re.sub("^.. ", "", str(resource))
        lservice  = re.sub(" .*$", "", str(resource))
        if (lservice.lower() == "fs") : store_type = "file"
        if (not ut.safeDirExist(directory)) : directory = BACKUP_DIRECTORY
        stores = StoreManager.check_stores(store_file)
        directory = directory + os.sep + ut.safeTimestamp() + "_" + store_type
        for store in stores["stores"]:
            if (pstore) and (pstore.lower() != store.lower()): continue
            if (store_type.lower() == "rest"):
                server = RestDataStore(entity_type=store["entity"], name_att=store["name_att"],
                                       desc_att=store["desc_att"], service=store["service"])
            else:
                server = FileDataStore(entity_type=store["entity"], name_att=store["name_att"],
                                       desc_att=store["desc_att"], service=store["service"])
            server.dump_all(directory=directory)
        sys = ut.get_sys()
        res = { "operation" : "back_up" , "status" : "success" , "directory" : directory , "system" : sys}
        return json.dumps(res, indent=2)


LOCAL_SERVICE     = ["LOCAL", "FILES", "FS"]
DATASTORE_SERVICE = ["AEP", "REST", "DS"]
WSO2_SERVICE      = ["WSO2", "APIM", "WS"]
SERVICES          = LOCAL_SERVICE + DATASTORE_SERVICE + WSO2_SERVICE

AEP_CATALOG_RESSOURCES = ["PROVIDERS", "ARTICLES", "CATEGORIES", "COLLECTIONS", "APIS", "API_BUNDLES"]
AEP_SUBSCRIPTION_RESSOURCES = ["SUBSCRIPTIONS", "API_CONSUMERS"]
AEP_APPLICATION_USER_PROFILES_RESSOURCES = ["ACCOUNTS", "SERVICES", "CONTACTS", "ROLES", "INDUSTRIES", "USECASES"]
AEP_RESSOURCES = AEP_CATALOG_RESSOURCES + AEP_APPLICATION_USER_PROFILES_RESSOURCES + AEP_SUBSCRIPTION_RESSOURCES

APIM_RESSOURCES = ["APIS", "POLICIES", "CATEGORIES", "PRODUCTS"]
DEVM_RESSOURCES = ["APPLICATIONS", "SUBSCRIPTIONS"]
ADM_RESSOURCES  = ["USERS", "SETTINGS"]
WSO2_RESSOURCES = APIM_RESSOURCES + DEVM_RESSOURCES + ADM_RESSOURCES

COMMANDS = ["LIST", "GET", "DELETE", "CREATE", "UPDATE", "BROWSE", "DISPLAY", "EDIT", "OPENAPI", "SCHEMA",
            "HELP", "CONFIG", "VERBOSE", "DS", "FS", "WS", "EXIT"]

"""

# Admin Wso2UsersManager

 add_user(self, userName: str, credential: str, roleList : str, requirePasswordChange : bool = False):
 list_users(self):
 delete_user(self, userName: str):
 is_user(self, userName: str):
 get_user_role(self, userName: str):

# Publisher Wso2ApiManager

 settings_get(self):

 api_list(self, names : bool = False, names_versions : bool = False, ids : bool = False, versions: bool = False):
 api_get(self, api_id):
 api_details(self, api_id):
 api_id_by_name(self, name : str, version: str = None) -> str:
 api_create(self, api : str, swagger_file : str = None, publish : bool = False) -> str:
 api_publish(self, api_id):
 api_delete(self, api_id : str = None, name : str = None, version: str = None):

 policy_type(self, policy_type : str = "advanced"):
 policy_create(self, policy : str, policy_type : str = "advanced"):
 policy_list(self, policy_type : str = "advanced"):
 policy_get(self, policy_id, policy_type : str = "advanced"):
 policy_delete(self, policy_id, policy_type : str = "advanced"):

 category_get(self, category_id):
 category_list(self, service="admin"):
 category_create(self, category : str):
 category_delete(self, category_id):

 product_list(self):
 product_get(self, product_id):
 product_details(self, product_id):
 product_delete(self, product_id):
 product_create(self, api : str):


# Dev  Wso2ApiDevManager

 settings_get(self):

 application_create(self, application : str):
 application_list(self, names : bool = True):
 application_get(self, app_id):
 application_delete(self, app_id: str = None, name: str = None):
 application_details(self, app_id):
 application_id_by_name(self, name : str) -> str:
 application_get_keys(self, app_id : str = None, app_name : str = None):
 application_generate_keys(self, app_id : str = None, app_name : str = None):

 subscription_create(self, subscription : str):
 subscription_list(self, applicationId: str = None, apiId: str = None):
 subscription_get(self, subs_id):
 subscription_delete(self, subs_id: str = None, name: str = None):
 subscription_details(self, subs_id):
 subscription_id(self, app_id : str, api_id : str) -> str:
 subscribe(self, app_id : str = None, app_name : str = None, api_id : str = None, api_name : str = None, api_version : str = None, policy : str = "Unlimited"):
 unsubscribe(self, app_id : str = None, app_name : str = None, api_id : str = None, api_name : str = None, api_version : str = None):

"""

###
### Command Line Controller
###


class AepCtl:

    @staticmethod
    def error(resource: str, command: str, message: str, help_text: str = None) -> str:
        text = ""
        if (resource != ""): text = text + resource.lower() + " "
        if (command != ""): text = text + command.lower() + " "
        if (text != ""): text = text + ": "
        error_text = text + message if (message) else text + "Error."
        logger.info(error_text)
        ut.Term.print_red(error_text)
        ut.Term.print_blue(help_text)
        return error_text

    @staticmethod
    def help(resource: str, commands, options=None) -> str:
        if (resource == ""):
            resource_text = ""
            sep = ""
            for command in commands:
                resource_text = resource_text + sep + command
                sep = "|"
            resource_text = "[" + resource_text + "]"
            command_text = "help"
            options_text = ""
            help_text = resource_text.lower() + " " + command_text.lower() + " " + options_text
            ut.Term.print_blue(help_text)
            return help_text
        resource_text = resource.lower()
        if (isinstance(commands, dict)):
            command_text = ""
            sep = ""
            for command in commands[resource.lower()]:
                command_text = command_text + sep + command
                sep = "|"
            command_text = "[" + command_text + "]"
            options_text = "help"
            help_text = resource_text.lower() + " " + command_text.lower() + " " + options_text
            ut.Term.print_blue(help_text)
            return help_text
        command_text = commands.lower()
        if (isinstance(options, dict)):
            options_text = ""
            sep = ""
            if (not options[resource.lower()][commands.lower()]):
                options_text = ""
            else:
                for command in options[resource.lower()][commands.lower()]:
                    options_text = options_text + sep + command
                    sep = "|"
                options_text = "[" + options_text + "]"
        elif (options):
            options_text = "[" + options + "]"
        else:
            options_text = "help"
        help_text = resource_text.lower() + " " + command_text.lower() + " " + options_text
        logger.info(help_text)
        ut.Term.print_blue(help_text)
        return help_text

    @staticmethod
    def print(resource: str, data: Union[dict, str, list], idName: str = None) -> str:
        if (idName):
            name = str(resource).lower() + "/" + str(idName)
        else:
            name = str(resource).lower()
        if isinstance(data, dict):
            print_text = json.dumps(ut.SuperDict(data=data, name=name).clean().getAsData(), indent=2)
        elif isinstance(data, list):
            print_text = json.dumps(ut.SuperDict(data=data, name=resource).clean().get(resource), indent=2)
        else:
            print_text = str(data)
        logger.info(print_text)
        ut.Term.print_green(print_text)
        return print_text

    @staticmethod
    def browse(resource, entry, idName: str = "") -> str:
        name = str(resource).lower() + " " + str(idName)
        utg.dataBrowserForm(data=ut.SuperDict(entry, name=name).clean(), style="TREE",
                            formats_choices=["Json", "Yaml", "Flat"], read_only=True,
                            name=name, index_prefix=resource.capitalize() + " ").run()
        return AepCtl.print(resource, entry, idName)

    @staticmethod
    def display(resource, entry, idName) -> str:
        name = str(resource).lower() + " " + str(idName)
        utg.dataBrowserForm(data=ut.SuperDict(entry, name=name).clean(), style="TREE",
                            formats_choices=["Json", "Yaml", "Flat"], read_only=True,
                            name=name, index_prefix=resource.capitalize() + " ").run()
        return AepCtl.print(resource, entry, idName)

    @staticmethod
    def handle_output(entry, resource, command, idName: str = "", fileName: str = None) -> str:
        yaml_text = "\n" + ut.to_yaml(entry, indent=2)
        json_text = "\n" + ut.to_json(entry, indent=2)
        if (command.upper() == "DISPLAY"):
            AepCtl.display(resource, entry, resource.lower() + " - " + str(idName))
            return yaml_text
        elif (idName.upper() == "JSON"):
            ut.Term.print_green(json_text)
            return json_text
        elif (idName.upper() == "YAML"):
            ut.Term.print_green(yaml_text)
            return yaml_text
        elif (idName.upper() in ["", "FILE"]):
            ut.saveYamlFile(entry, fileName)
            AepCtl.print(resource, "Yaml saved in : " + fileName)
            return yaml_text
        else:
            ut.saveYamlFile(entry, idName)
            AepCtl.print(resource, "Yaml saved in : " + idName)
            return yaml_text
        return yaml_text

    @staticmethod
    def display_help():
        console = Console()
        with open("aepctl.md", "r+") as help_file:
            console.print(Markdown(help_file.read()))

    @staticmethod
    def display_config():
        ut.Term.print_green(str(ut.getCurrentConfiguration()))

    @staticmethod
    def prompt_list_to_dict(elist: list) -> dict:
        ldc = dict()
        for elem in elist:
            ldc[elem.lower()] = None
        return ldc

    policy_type = {"application", "custom", "advanced", "deny-policies", "subscription", "mediation"}

    wso2_commands = {
        "settings": {
            "help": None,
            "get": {"apim", "dev", "admin", "help"},
            "display": {"apim", "dev", "admin", "help"},
        },
        "apis": {
            "help": None,
            "list": {"entries", "names", "ids", "help"},
            "get": {"<id>", "<name/version>", "help"},
            "display": {"<id>", "<name/version>", "help"},
            "details": {"<id>", "all", "help"},
            "browse": {"<id>", "all", "help"}
        },
        "policies": {
            "help": None,
            "list": {"entries", "names", "ids", "help"},
            "browse": {"<id>", "all", "help"},
            "get": {"<id>", "help"},
            "display": {"<id>", "help"}
        },
        "categories": {
            "help": None,
            "list": {"entries", "names", "ids", "help"},
            "browse": {"<id>", "all", "help"},
            "get": {"<id>", "help"},
            "display": {"<id>", "help"}
        },
        "products": {
            "help": None,
            "list": {"entries", "names", "ids", "help"},
            "browse": {"<id>", "all", "help"},
            "get": {"<id>", "help"},
            "display": {"<id>", "help"}
        },
    }

    @staticmethod
    def handle_ws02_command(arguments):

        logger.info("handle_ws02_command")

        resource = arguments["RESSOURCE"] if (("RESSOURCE" in arguments) and (arguments["RESSOURCE"])) else ""
        command = arguments["COMMAND"].upper() if (("COMMAND" in arguments) and (arguments["COMMAND"])) else ""
        idName = arguments["ID"] if (("ID" in arguments) and (arguments["ID"])) else ""
        entry = arguments["PAYLOAD"] if (("PAYLOAD" in arguments) and (arguments["PAYLOAD"])) else ""
        entry = re.sub("\\\"", '"', entry)
        service = arguments["SERVICE"] if (("SERVICE" in arguments) and (arguments["SERVICE"])) else "rest"

        admm = Wso2UsersManager()
        apim = Wso2ApiManager()
        devm = Wso2ApiDevManager()

        if (command.upper() in ["HELP"]):  # <resource>  help
            return AepCtl.help(resource, AepCtl.wso2_commands)
        if (resource.upper() in ["HELP"]):  # <resource>  help
            return AepCtl.help(resource, AepCtl.wso2_commands)
        if (idName.upper() in ["HELP"]):  # <resource> <command> help
            return AepCtl.help(resource, command, AepCtl.wso2_commands)

        # settings_get(self):
        if (resource.upper() == "SETTINGS"):
            # settings_get(self):
            if (command in ["GET", "DISPLAY"]):  # settings get|display
                if (idName.upper() in ["APIM", "PUBLISHER_PORTAL"]):
                    entry = apim.settings_get()
                    if (apim.isError()): return AepCtl.error(resource, command, apim.getError())
                elif (idName.upper() in ["ADMIN", "WSO2"]):
                    entry = admm.settings_get()
                    if (admm.isError()): return AepCtl.error(resource, command, apim.getError())
                elif (idName.upper() in ["DEV", "DEVELOPER_PORTAL"]):
                    entry = devm.settings_get()
                    if (devm.isError()): return AepCtl.error(resource, command, apim.getError())
                else:
                    return AepCtl.error(resource, command, "Unkown idName : " + idName)
                if (command.upper() == "GET"):  # settings display
                    return AepCtl.print(resource, entry, idName)
                elif (command.upper() == "DISPLAY"):  # settings display
                    return AepCtl.display(resource, entry, idName)
            else:
                return AepCtl.error(resource, command, "Unkown command : " + command)

        # Publisher Wso2ApiManager
        if (resource.upper() == "APIS"):
            # api_list(self, names: bool = False, names_versions: bool = False, ids: bool = False, versions: bool = False):
            # api_get(self, api_id):
            # api_details(self, api_id):
            # api_id_by_name(self, name: str, version: str = None) -> str:
            # api_create(self, api: str, swagger_file: str = None, publish: bool = False) -> str:
            # api_publish(self, api_id):
            # api_delete(self, api_id: str = None, name: str = None, version: str = None):
            if (command == "LIST"):  # apis list
                elist = apim.api_list(names_versions=(idName.lower() == "names"), ids=(idName.lower() == "ids"))
                if (apim.isError()): return AepCtl.error(resource, command, apim.getError())
                return AepCtl.print(resource, elist)
            if (command in ["GET", "DISPLAY"]):  # apis get|display id|name/version|help
                if ("/" in idName):  # apis get|display name/version
                    apid = apim.api_id_by_name(name=idName)
                else:  # apis get|display id
                    apid = idName
                entry = apim.api_get(api_id=apid)
                if (apim.isError()):
                    return AepCtl.error(resource, command, apim.getError())
                elif (command == "GET"):  # apis get
                    return AepCtl.print(resource, entry, idName)
                elif (command == "DISPLAY"):  # apis display
                    return AepCtl.display(resource, entry, idName)
                return None
            if (command in ["DETAILS", "BROWSE"]):  # apis details/browse id|all
                if (idName.upper() == "ALL"): idName = ""
                details = apim.api_details(api_id=idName).getAsData()
                # if (apim.isError()):
                #   return AepCtl.error(resource, command, apim.getError())
                if (command == "DETAILS"):  # apis browse id|all
                    return AepCtl.print(resource, details, idName)
                elif (command == "BROWSE"):  # apis browse id|all
                    return AepCtl.browse(resource, details, idName)
                else:
                    return AepCtl.error(resource, details, "Unkown command : " + command)
        if (resource.upper() == "POLICIES"):
            # "application", "custom", "advanced", "deny-policies", "subscription", "mediation"
            # policy_type(self, policy_type: str = "advanced"):
            # policy_list(self, policy_type: str = "advanced"):
            # policy_get(self, policy_id, policy_type: str = "advanced"):
            # policy_create(self, policy: str, policy_type: str = "advanced"):
            # policy_delete(self, policy_id, policy_type: str = "advanced"):
            if (command in ["LIST", "BROWSE"]):  # apis list
                elist = apim.policy_list(policyType=idName)
                if (apim.isError()):
                    AepCtl.error(resource, command, apim.getError())
                elif (command == "LIST"):  # policies list
                    AepCtl.print(resource, elist)
                elif (command == "BROWSE"):  # policies browse
                    AepCtl.browse(resource, elist)
                return None
            if (command == "GET" or command == "DISPLAY"):  # policies get|display id|name
                entry = apim.policy_get(policy_id=idName)
                if (command == "GET"):  # policies display
                    AepCtl.print(resource, entry, idName)
                elif (command == "DISPLAY"):  # policies display
                    AepCtl.display(resource, entry, idName)
                return None
        if (resource.upper() == "CATEGORIES"):
            # category_get(self, category_id):
            # category_list(self, service="admin"):
            # category_create(self, category: str):
            # category_delete(self, category_id):
            if (command in ["LIST", "BROWSE"]):  # categories list
                elist = apim.category_list(service="admin")
                if (apim.isError()):
                    AepCtl.error(resource, command, apim.getError())
                elif (command == "LIST"):  # policies list
                    AepCtl.print(resource, elist)
                elif (command == "BROWSE"):  # policies browse
                    AepCtl.browse(resource, elist)
                return None
            if (command == "GET" or command == "DISPLAY"):  # categories get|display id|name
                entry = apim.category_get(category_id=idName)
                if (command == "GET"):  # policies display
                    AepCtl.print(resource, entry, idName)
                elif (command == "DISPLAY"):  # policies display
                    AepCtl.display(resource, entry, idName)
                return None
        if (resource.upper() == "PRODUCTS"):
            # product_list(self):
            # product_get(self, product_id):
            # product_details(self, product_id):
            # product_delete(self, product_id):
            # product_create(self, api: str):
            if (command in ["LIST", "BROWSE"]):  # products list
                elist = apim.product_list()
                if (apim.isError()):
                    AepCtl.error(resource, command, apim.getError())
                elif (command == "LIST"):  # products list
                    AepCtl.print(resource, elist)
                elif (command == "BROWSE"):  # products browse
                    AepCtl.browse(resource, elist)
                return None
            if (command == "GET" or command == "DISPLAY"):  # products get|display id|name
                entry = apim.product_get(category_id=idName)
                if (command == "GET"):  # products display
                    AepCtl.print(resource, entry, idName)
                elif (command == "DISPLAY"):  # products display
                    AepCtl.display(resource, entry, idName)
                return None

        # Dev Wso2ApiDevManager
        if (resource.upper() == "APPLICATIONS"):
            # application_create(self, application: str):
            # application_list(self, names: bool = True):
            # application_get(self, app_id):
            # application_delete(self, app_id: str = None, name: str = None):
            # application_details(self, app_id):
            # application_id_by_name(self, name: str) -> str:
            # application_get_keys(self, app_id: str = None, app_name: str = None):
            # application_generate_keys(self, app_id: str = None, app_name: str = None):
            elist = devm.application_list()
            ut.Term.print_green(json.dumps(elist, indent=2))
            return None
        if (resource.upper() == "SUBSCRIPTIONS"):
            # subscription_create(self, subscription: str):
            # subscription_list(self, applicationId: str = None, apiId: str = None):
            # subscription_get(self, subs_id):
            # subscription_delete(self, subs_id: str = None, name: str = None):
            # subscription_details(self, subs_id):
            # subscription_id(self, app_id: str, api_id: str) -> str:
            # subscribe(self,  app_id: str = None, app_name: str = None, api_id: str = None, api_name: str = None, api_version: str = None, policy: str = "Unlimited"):
            # unsubscribe(self, app_id: str = None, app_name: str = None, api_id: str = None, api_name: str = None, api_version: str = None):
            elist = devm.subscription_list()
            ut.Term.print_green(json.dumps(elist, indent=2))
            return None
        if (resource.upper() == "USERS"):
            # Admin Wso2UsersManager
            # add_user(self, userName: str, credential: str, roleList: str, requirePasswordChange: bool = False):
            # list_users(self):
            # delete_user(self, userName: str):
            # is_user(self, userName: str):
            # get_user_role(self, userName: str):

            elist = admm.list_users()
            ut.Term.print_green(json.dumps(elist, indent=2))
            return None

    handle_output_commands = {
        "json": None,
        "yaml": None,
        "display": None,
        "file": {"<filename>"},
    }

    ds_commands = {
        "get": {
            "<id>": None,
            "<name>": None,
            "schema": handle_output_commands,
            "openapi": handle_output_commands,
        },
        "display": {
            "<id>"    : None,
            "<name>"  : None,
            "schema"  : handle_output_commands,
            "openapi" : handle_output_commands,
        },
        "list": {
            "entries" : None,
            "count"   : None,
            "names"   : None,
            "ids"     : None,
        },
        "browse": None,
        "create": {
            "<json / yaml fileName>" : None,
            "<json / yaml payload>"  : None,
        },
        "update": {
            "<json / yaml fileName>" : None,
            "<json / yaml payload>"  : None,
        },
        "delete": {
            "all"      : None,
            "<idName>" : None,
        },
        "backup"  : PathCompleter(expanduser=True),  #  SystemCompleter(),  # PathCompleter(expanduser=True),
        "openapi" : handle_output_commands,
        "schema"  : handle_output_commands,
    }

    @staticmethod
    def handle_aep_command(arguments):

        logger.info("handle_aep_command")

        resource = arguments["RESSOURCE"]       if (("RESSOURCE" in arguments) and (arguments["RESSOURCE"])) else ""
        command  = arguments["COMMAND"].upper() if (("COMMAND" in arguments)   and (arguments["COMMAND"]))   else ""
        idName   = arguments["ID"]              if (("ID" in arguments)        and (arguments["ID"]))        else ""
        entry    = arguments["PAYLOAD"]         if (("PAYLOAD" in arguments)   and (arguments["PAYLOAD"]))   else ""
        entry    = re.sub("\\\"", '"', entry)
        service  = arguments["SERVICE"]         if (("SERVICE" in arguments)   and (arguments["SERVICE"]))   else "rest"
        payload  = arguments["PAYLOAD"]         if (("PAYLOAD" in arguments)   and (arguments["PAYLOAD"]))   else ""

        if (service.upper() in LOCAL_SERVICE):
            service = "file"
        else:
            service = "rest"

        if (command.upper() in ["HELP"]):  # <resource>  help
            return AepCtl.help(resource, AepCtl.aep_commands)
        if (resource.upper() in ["HELP"]):  # <command> help
            return AepCtl.help(resource, AepCtl.aep_commands)
        if ((command == "") and (resource == "")):
            return AepCtl.error(resource, command, "No command nor resource specified.",AepCtl.help(resource, AepCtl.aep_commands))
        try:
            store = StoreManager().getStore(resource, file=(service == "file"))
        except Exception as ex:
            return AepCtl.error(resource, command, "Store Access Error.", AepCtl.print("resources", str(ex).replace("\\n", "\n")))
        if (not store):
            return AepCtl.error(resource, command, "Invalid Resource.", AepCtl.print("resources", str(StoreManager.list_store_entities())))
        if (resource.upper() == "STORES"):
            return AepCtl.print(resource, str(StoreManager.list_store_entities()))
        if (command.upper() in ["OPENAPI"]):
            openapi = StoreManager.get_openapi(entity=resource)
            command = idName
            return AepCtl.handle_output(openapi, resource, command, fileName="OpenAPI_" + resource + ".yaml")
        elif (command.upper() in ["SCHEMA"]):
            schema = StoreManager.get_schema(entity=resource)
            command = idName
            return AepCtl.handle_output(schema, resource, command, fileName="Schema_" + resource + ".yaml")
        elif (command.upper() in ["LIST", "BROWSE"]):
            if (resource.upper() == "STORES"):
                return AepCtl.print(resource, StoreManager.list_store_entities())
            entry_list = store.list(ids=(idName.lower() == "ids"), names=(idName.lower() == "names"),
                                    count=(idName.lower() == "count"))
            if (store.error()):
                return AepCtl.error(resource, command, store.error())
            if (command == "LIST"):
                return AepCtl.print(resource, entry_list, resource)
            if (command == "BROWSE"):
                return AepCtl.browse(resource, entry_list, resource)
        elif (command.upper() in ["GET", "DISPLAY"]):
            if (idName.upper() == ""):
                return AepCtl.error(resource, command, "No ID nor Name provided.")
            if (idName.upper() == "SCHEMA"):
                schema = StoreManager.get_schema(entity=resource)
                return AepCtl.handle_output(schema, resource, command, fileName="Schema_" + resource + ".yaml")
            if (idName.upper() == "OPENAPI"):
                openapi = StoreManager.get_openapi(entity=resource)
                return AepCtl.handle_output(openapi, resource, command, fileName="OpenAPI_" + resource + ".yaml")
            entry = store.get(idName)
            if (store.error()):         return AepCtl.error(resource, command, store.error())
            if (not entry):             return AepCtl.error(resource, command, "No such entry : " + idName)
            if (command == "GET"):      return AepCtl.print(resource, entry, idName)
            if (command == "DISPLAY"):  return AepCtl.display(resource, entry, idName)
        elif (command.upper() in ["DELETE"]):
            if (idName.upper() == "ALL"):
                entries = store.delete_all()
                if (store.error()): return AepCtl.error(resource, command, store.error())
                return AepCtl.print(resource, entries)
            else:
                entry = store.delete(idName)
                if (store.error()): return AepCtl.error(resource, command, store.error())
                return AepCtl.print(resource, entry)
        elif (command.upper() in ["CREATE", "UPDATE"]):
            filename = payload
            payload  = payload
            if (ut.safeFileExist(filename)):
                logger.info("Filename : " + filename)
                payload = ut.loadFileData(filename)
            else:
                logger.info("Payload : " + payload)
                payload = ut.loadDataContent(payload)
            if (not payload):
                return AepCtl.error(resource, command, "Cannot JSON/YAML Decode : " + filename)
            logger.info("Entry : \n" + json.dumps(payload, indent=2))
            if (store.exist(payload[store.id_att])):
                command = "UPDATE"
            else:
                command = "CREATE"
            if (command == "UPDATE"):  entry = store.update(payload)
            if (command == "CREATE"):  entry = store.create(payload)
            if (store.error()):
                return AepCtl.error(resource, command, store.error())
            return AepCtl.print(resource, entry)
        elif (command.upper() in ["BACKUP"]):
            directory = (idName + " " + str(payload)).strip()
            logger.info("BackUp Dir : "+directory)
            res = StoreManager().store_back_up(resource=resource, store_type=service, directory=directory)
            return AepCtl.print(resource, res)
        else:
            return AepCtl.error(resource, command, "Invalid Command.", AepCtl.help(resource, AepCtl.aep_commands))
        return None

    @staticmethod
    def handle_command(arguments):

        resource = arguments["RESSOURCE"].upper() if (("RESSOURCE" in arguments) and (arguments["RESSOURCE"])) else ""
        command = arguments["COMMAND"].upper() if (("COMMAND" in arguments) and (arguments["COMMAND"])) else ""
        idName = arguments["ID"] if (("ID" in arguments) and (arguments["ID"])) else ""
        service = arguments["SERVICE"].upper() if (("SERVICE" in arguments) and (arguments["SERVICE"])) else "rest"
        entry = arguments["PAYLOAD"] if (("PAYLOAD" in arguments) and (arguments["PAYLOAD"])) else ""
        entry = re.sub("\\\"", '"', entry)
        arguments["PAYLOAD"] = entry
        if (resource.upper() in COMMANDS):
            tmp = command
            command = resource.upper()
            resource = tmp.upper()
            arguments["RESSOURCE"] = resource
            arguments["COMMAND"] = command
        logger.info("SERVICE   = " + str(service))
        logger.info("RESSOURCE = " + str(resource))
        logger.info("COMMAND   = " + str(command))
        logger.info("IDNAME    = " + str(idName))
        logger.info("PAYLOAD   = " + str(entry))

        if (command.upper() in ["CONFIG", "CFG", "C"]):
            return AepCtl.display_config()
        elif (command.upper() in ["VERBOSE", "V"]):
            return ut.Verbose.swap_verbose()
        elif (service.upper() in WSO2_SERVICE):
            return AepCtl.handle_ws02_command(arguments)
        elif (service.upper() in LOCAL_SERVICE):
            return AepCtl.handle_aep_command(arguments)
        elif (service.upper() in DATASTORE_SERVICE):
            return AepCtl.handle_aep_command(arguments)
        elif (resource.upper() in AEP_RESSOURCES):
            return AepCtl.handle_aep_command(arguments)
        elif (resource.upper() in WSO2_RESSOURCES):
            return AepCtl.handle_ws02_command(arguments)
        else:
            ut.Term.print_red("Unknown Command or Option : " + resource)
            ut.Term.print_green(read_command_line_args(None, p_usage=True))
            return None


###
### Prompt Completion
###

aep_commands = AepCtl.prompt_list_to_dict(AEP_RESSOURCES)
for cmd in aep_commands:
    aep_commands[cmd] = AepCtl.ds_commands
aep_commands["help"] = None
aep_commands["stores"] = None

dc            = AepCtl.prompt_list_to_dict(COMMANDS)
dc["ws"]      = AepCtl.wso2_commands
dc["fs"]      = aep_commands
dc["ds"]      = aep_commands
# dc["payload"] = PathCompleter(expanduser=True)
cmd_completer = NestedCompleter.from_nested_dict(dc)


def interactive_prompt():
    ut.Verbose.init_verbose(False)
    current_context = "ds"
    try:
        history = FileHistory(filename=AEPCTL_HOME_DIR + os.sep + "history")
        session = PromptSession(history=history)
    except Exception as e:
        # No proper terminal support
        print(str(e))
        session = None
    command  = ""
    ctrl_c   = False
    while command != "exit":
        if (session):
            if (current_context == "fs"): text = HTML("eapctl <IndianRed>"      + current_context + "</IndianRed>" + " > ")
            if (current_context == "ds"): text = HTML("eapctl <MediumSeaGreen>" + current_context + "</MediumSeaGreen>" + " > ")
            if (current_context == "ws"): text = HTML("eapctl <DeepSkyBlue>"    + current_context + "</DeepSkyBlue>" + " > ")
            try:
                command = session.prompt(text, completer=cmd_completer, complete_while_typing=True)
                ctrl_c  = False
            except KeyboardInterrupt :   # Capture CTRL-C Reset Line
                if (ctrl_c) : return     # Double CTRL-C Exit
                ctrl_c = True
                continue
        else:
            command = input("eapctl " + current_context + " > ")
        logger.info("Prompt command : " + command)
        if (command.strip() in ["", " "]):
            continue
        if (command.upper() in ["EXIT", "X", "QUIT", "Q", "BYE", "B"]):
            quit(0)
            continue
        if (command.upper() in ["VERBOSE", "V"]):
            ut.Verbose.swap_verbose()
            continue
        if (command.upper() == "DS"):
            ut.Term.print_green("On Remote Rest DataStore")
            current_context = "ds"
            continue
        if (command.upper() == "FS"):
            ut.Term.print_red("On Local File DataStore")
            current_context = "fs"
            continue
        if (command.upper() == "WS"):
            ut.Term.print_blue("On WSO2 API Manager")
            current_context = "ws"
            continue
        command = current_context + " " + command
        res = main(command, interactive=True)
        logger.debug(res)
        # print(str(res))


###
### Main
###


def read_command_line_args(argv, p_usage : bool = False) -> Union[str, dict, None]:
    global CONFIG_FILE

    usage = """
Usage: -h -v -c <ConfigurationFile.json> [<service>] [<resource>] [<command>] [<identifier>] [<payload>] -p <PayloadFile.json>
       -h --help        : Usage help 
       -v --verbose     : Verbose     
       -c --cfile <ConfigurationFile.json> : Use Configuration File 
       -s --service     : Service      
       -c --command     : Command 
       -f --filestore   : local filestore  service (default is rest datastore service)     
       -w --apim --wso2 : wso2 api manager service (default is rest datastore service)     
       -p --payload     : Payload     
Services  : """ + str(SERVICES) + """   
Resources :
  - AEP   : """ + str(AEP_RESSOURCES) + """ 
  - APIM  : """ + str(WSO2_RESSOURCES) + """ 
Commands  : """ + str(COMMANDS) + """  
Payload   : <JSON>, JSON_FileName, YAML_FileName  
"""

    if (p_usage) :
        return usage

    if isinstance(argv, str):
        argv = argv.split()

    # logger.info("Command Line Arguments : " + str(argv))

    cl_args = dict()
    cl_args["RESSOURCE"]      = None
    cl_args["COMMAND"]        = None
    cl_args["ID"]             = None
    cl_args["PAYLOAD"]        = None
    cl_args["SERVICE"]        = "ds"
    cl_args["CONFIG_FILE"]    = None
    cl_args["VERBOSE"]        = False

    try:
        opts, args = getopt.getopt(argv, "hvdc:p:s:fw", ["help", "verbose", "debug",  "config=", "payload=", "service=", "filestore", "wso2"])
    except getopt.GetoptError as e:
        ut.Term.print_yellow("Command Line Arguments : " + str(argv))
        ut.Term.print_red("GetoptError : " + str(e))
        ut.Term.print_blue(usage)
        return None
    for opt, arg in opts:
        if opt.lower() in ("-h", "--help"):
            ut.Term.print_blue(usage)
            # display_help()
            return None
        elif opt.lower() in ("-c", "--cfile", "--config"):
            CONFIG_FILE = arg
            cl_args["CONFIG_FILE"] = CONFIG_FILE
            if (not ut.safeFileExist(CONFIG_FILE)):
                ut.Term.print_red("File not found : " + CONFIG_FILE)
                ut.Term.print_blue(usage)
                return None
            continue
        elif opt.lower() in ("-p", "--payload", "--entry"):
            filename = arg
            if (not ut.safeFileExist(filename)):
                ut.Term.print_red("File not found : " + filename)
                ut.Term.print_blue(usage)
                return None
            PAYLOAD = ut.loadFileContent(filename)
            if (not PAYLOAD):
                ut.Term.print_red("Cannot JSON Decode : " + PAYLOAD)
                ut.Term.print_blue(usage)
                return None
            cl_args["PAYLOAD"] = PAYLOAD
            continue
        elif opt.lower() in ("-f", "-fs", "--filestore"):
            cl_args["SERVICE"] = "fs"
            ut.Term.setVerbose(True)
            continue
        elif opt.lower() in ("-w", "-ws", "-wso2", "-apim"):
            cl_args["SERVICE"] = "ws"
            ut.Term.setVerbose(True)
            continue
        elif opt.lower() in ("-s", "-service", "-svc"):
            service = arg
            if (service.upper() not in SERVICES):
                ut.Term.print_red  ("Invalid Service : " + str(service))
                ut.Term.print_green("Known Services  : " + str(SERVICES))
                ut.Term.print_blue(usage)
                return None
            cl_args["SERVICE"] = service.upper()
            continue
        elif opt.lower() in ("-c", "-command", "-cmd"):
            command = arg
            if (command.upper() not in COMMANDS):
                ut.Term.print_red("Invalid Command : "   + str(service))
                ut.Term.print_green("Known Commands  : " + str(COMMANDS))
                ut.Term.print_blue(usage)
                return None
            cl_args["COMMAND"] = command.upper()
            continue
        elif opt.lower() in ("-v", "-verbose"):
            cl_args["VERBOSE"] = True
            ut.Term.setVerbose(True)
            continue
        else :
            ut.Term.print_red("Invalid Command Line Option : " + opt)
            ut.Term.print_blue(usage)
            return None
    for arg in args :
        if   (arg.upper() in SERVICES)  :
            cl_args["SERVICE"]   = arg
            continue
        if   (not cl_args["RESSOURCE"]) : cl_args["RESSOURCE"] = arg
        elif (not cl_args["COMMAND"])   : cl_args["COMMAND"]   = arg
        elif (not cl_args["ID"])        : cl_args["ID"]        = arg
        elif (not cl_args["PAYLOAD"])   : cl_args["PAYLOAD"]   = arg
        else : cl_args["PAYLOAD"] = cl_args["PAYLOAD"] + " " + arg
        continue
    # logger.info("Command Line Args : \n" + json.dumps(cl_args, indent=3))
    return cl_args


def main(argv, interactive : bool = False):
    global AEPCTL_Configuration

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    args = read_command_line_args(argv)

    if (args == None):
        return None

    if (not interactive):
        ut.Verbose.set_verbose(p_verbose=args["VERBOSE"], silent=True)
    else:
        ut.Verbose.init_verbose()

    logger.info("Command Line Arguments : " + str(argv))
    logger.info("Command Line Args : \n" + json.dumps(args, indent=3))

    logger.info("AEPCTL_HOME_DIR : " + str(AEPCTL_HOME_DIR))
    logger.info("AEPCTL_WORK_DIR : " + str(AEPCTL_WORK_DIR))
    logger.info("AEPCTL_ROOT_DIR : " + str(AEPCTL_ROOT_DIR))

    AEPCTL_Configuration = ut.init_Configuration(cfg_filename=AEPCTL_Configuration_FileName,  # Default File Name
                                                 cmd_line_arg=CONFIG_FILE,                    # Command Line Arg. FileName
                                                 env_cfg_var="AEPCTL_CONFIGURATION",          # Env Var with the FileName
                                                 default_cfg=def_AEPCTL_Configuration,        # Default Configuration
                                                 tag="AEPCTL Configuration")

    return AepCtl.handle_command(args)


if __name__ == '__main__':
    if (len(sys.argv[1:]) == 0):
        # No arguments - interactive session
        interactive_prompt()
    else:
        # Arguments - one time command
        main(argv=sys.argv[1:], interactive=False)


###
### Unit Tests
###


class TestMain(unittest.TestCase):

    def setUp(self) -> None:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def testCommandLineArguments(self):
        main(" -v  providers list names")

    def testInteractive(self):
        command = input("eapctl > ")
        while command != "exit" :
            res = main(command, interactive=True)
            logger.debug(res)
            # print(str(res))
            command = input("eapctl > ")


# Need WSO2 Server to test this
class TestWso2Manager(unittest.TestCase):

    def setUp(self) -> None:
        self.storeManager = StoreManager()
        self.userManager  = Wso2UsersManager()
        self.apiManager   = Wso2ApiManager()
        self.devManager   = Wso2ApiDevManager()
        self.apiCatalog   = RestDataStore()
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def test_userManager(self):  # Need WSO2 server to test this
        self.assertEqual("false",           self.userManager.is_user("apicreator"))
        self.assertNotIn("apicreator",      self.userManager.list_users())
        self.assertEqual("Success 202",     self.userManager.add_user("apicreator", "apicreator", "Internal/creator", False))
        self.assertIn("apicreator",         self.userManager.list_users())
        self.assertEqual("true",            self.userManager.is_user("apicreator"))
        self.assertIn("Internal/creator",   self.userManager.get_user_role("apicreator"))
        self.assertEqual("Success 202",     self.userManager.delete_user("apicreator"))
        self.assertNotIn("apicreator",      self.userManager.list_users())
        self.assertEqual("false",           self.userManager.is_user("apicreator"))

    def test_policy(self):  # Need WSO2 server to test this
        self.apiManager.authentify()
        self.apiManager.policy_list(policy_type="subscription")
        print(str(self.apiManager.d_data.get("count")))
        print(str(self.apiManager.d_data.get("list/0")))
        policy_create = """
        {
          "policyName": "TestPolicy2",
          "displayName": "TestPolicy2",
          "description": "Description of TestPolicy2",
          "type": "SubscriptionThrottlePolicy",
          "defaultLimit": {
            "type": "REQUESTCOUNTLIMIT",
            "requestCount": {
              "timeUnit": "min",
              "unitTime": 1,
              "requestCount": 5
            }
          },
          "rateLimitCount": 5,
          "rateLimitTimeUnit": "sec",
          "subscriberCount": 10,
          "customAttributes": [],
          "stopOnQuotaReach": true,
          "billingPlan": "FREE"
        }
                """
        self.apiManager.policy_create(policy=policy_create,    policy_type="subscription")
        if (not self.apiManager.isError()):
            policy_id = self.apiManager.d_data.get("policyId")
            print(str(policy_id))
            self.apiManager.policy_get(policy_id=policy_id,    policy_type="subscription")
            self.apiManager.policy_delete(policy_id=policy_id, policy_type="subscription")
        else:
            print(str("Creation Error"))

    def test_apis(self):  # Need WSO2 server to test this
        self.apiManager.authentify()
        self.apiManager.category_list()
        self.apiManager.api_list()
        apid = self.apiManager.api_id_get_by_name("3gpp-as-session-with-qos-4", "1.1.4")
        self.apiManager.api_delete(apid)
        print(str(self.apiManager.d_data.get("count")))
        print(str(self.apiManager.d_data.get("list/0")))
        api_id = self.apiManager.api_get("5b70eaba-be85-4c76-9200-b6c116fd97cb")
        api_create = """
{
  "name": "3gpp-as-session-with-qos-4",
  "description": "",
  "context": "/qos",
  "version": "1.1.4",
  "provider": "admin",
  "lifeCycleStatus": "CREATED",
  "wsdlInfo": {
    "type": "ZIP"
  },
  "responseCachingEnabled": false,
  "cacheTimeout": 300,
  "hasThumbnail": false,
  "isDefaultVersion": false,
  "isRevision": false,
  "revisionId": 0,
  "enableSchemaValidation": false,
  "type": "HTTP",
  "transport": [
    "http",
    "https"
  ],
  "tags": [
  ],
  "policies": [
    "TestPolicy1"
  ],
  "apiThrottlingPolicy": "Unlimited",
  "authorizationHeader": "Authorization",
  "securityScheme": [
    "oauth2",
    "oauth_basic_auth_api_key_mandatory"
  ],
  "maxTps": {
    "production": 1000,
    "sandbox": 1000
  },
  "visibility": "PUBLIC",
  "visibleRoles": [],
  "visibleTenants": [],
  "mediationPolicies": [
  ],
  "subscriptionAvailability": "CURRENT_TENANT",
  "subscriptionAvailableTenants": [],
  "additionalProperties": [
  ],
  "accessControl": "NONE",
  "accessControlRoles": [],
  "businessInformation": {
  },
  "corsConfiguration": {
    "corsConfigurationEnabled": false,
    "accessControlAllowOrigins": [
      "*"
    ],
    "accessControlAllowCredentials": false,
    "accessControlAllowHeaders": [
      "authorization",
      "Access-Control-Allow-Origin",
      "Content-Type",
      "SOAPAction",
      "apikey",
      "Internal-Key"
    ],
    "accessControlAllowMethods": [
      "GET",
      "PUT",
      "POST",
      "DELETE",
      "PATCH",
      "OPTIONS"
    ]
  },
  "websubSubscriptionConfiguration": {
    "enable": false,
    "secret": "",
    "signingAlgorithm": "SHA1",
    "signatureHeader": "x-hub-signature"
  },
  "createdTime": "2022-02-14 18:00:00.000",
  "lastUpdatedTime": "2022-02-14 18:00:00.000",
  "endpointConfig": {
    "endpoint_type": "http",
    "sandbox_endpoints": {
      "url": "http://service-hostname:8080/3gpp-as-session-with-qos/v1/"
    },
    "production_endpoints": {
      "url": "http://service-hostname:8080/3gpp-as-session-with-qos/v1/"
    }
  },
  "endpointImplementationType": "ENDPOINT",
  "scopes": [
  ],
  "operations": [
    {
      "target": "/order/{orderId}",
      "verb": "POST",
      "authType": "Application & Application User",
      "throttlingPolicy": "Unlimited"
    },

    {
    "id": "",
    "target": "/{scsAsId}/subscriptions",
    "verb": "GET",
    "authType": "Application & Application User",
    "throttlingPolicy": "Unlimited",
    "scopes": [],
    "usedProductIds": []
    },{
    "id": "",
    "target": "/{scsAsId}/subscriptions",
    "verb": "POST",
    "authType": "Application & Application User",
    "throttlingPolicy": "Unlimited",
    "scopes": [],
    "usedProductIds": []
    },{
    "id": "",
    "target": "/{scsAsId}/subscriptions/{subscriptionId}",
    "verb": "GET",
    "authType": "Application & Application User",
    "throttlingPolicy": "Unlimited",
    "scopes": [],
    "usedProductIds": []
   },{
    "id": "",
    "target": "/{scsAsId}/subscriptions/{subscriptionId}",
    "verb": "PUT",
    "authType": "Application & Application User",
    "throttlingPolicy": "Unlimited",
    "scopes": [],
    "usedProductIds": []
   },{
    "id": "",
    "target": "/{scsAsId}/subscriptions/{subscriptionId}",
    "verb": "DELETE",
    "authType": "Application & Application User",
    "throttlingPolicy": "Unlimited",
    "scopes": [],
    "usedProductIds": []
   },{
    "id": "",
    "target": "/{scsAsId}/subscriptions/{subscriptionId}",
    "verb": "PATCH",
    "authType": "Application & Application User",
    "throttlingPolicy": "Unlimited",
    "scopes": [],
    "usedProductIds": []
   }
  ],
  "categories": [
  ],
  "advertiseInfo": {
    "advertised": false,
    "apiOwner": "admin",
    "vendor": "WSO2"
  }
}
            """
        self.apiManager.api_create(api=api_create, swagger_file="examples/rest-api/res.zip", publish=True)
        if (not self.apiManager.isError()):
            api_id = self.apiManager.d_data.get("id")
            print(str(api_id))
            self.apiManager.api_get(api_id=api_id)
            self.apiManager.api_delete(api_id=api_id)
        else:
            print(str("Creation Error"))

    def test_products(self):  # Need WSO2 server to test this
        self.apiManager.authentify()
        self.apiManager.product_list()
        product_id = self.apiManager.product_get("5b70eaba-be85-4c76-9200-b6c116fd97cb")

    def test_settings(self):  # Need WSO2 server to test this
        self.apiManager.authentify()
        settings = self.apiManager.settings_get()
        print(str(settings))
        api_details = self.apiManager.api_details(api_id="fe9b9052-51b3-4491-91aa-eba355d7fc35")
        print(str(api_details))
        product_details = self.apiManager.product_details(api_id="fe9b9052-51b3-4491-91aa-eba355d7fc35")
        print(str(product_details))

    def test_applications(self):  # Need WSO2 server to test this
        self.devManager.authentify()
        names = self.devManager.application_list(names=True)
        print(str(names))
        if ("TestQosApp" in names) :
            self.devManager.application_delete(name="TestQosApp")
        application_create = """
{
  "name": "TestQosApp",
  "throttlingPolicy": "Unlimited",
  "description": "Qos test application",
  "tokenType": "JWT",
  "groups": [],
  "attributes": {},
  "subscriptionScopes": []
}
        """
        self.devManager.application_create(application=application_create)
        if (not self.devManager.isError()):
            application_id = self.devManager.d_data.get("id")
            print(str(application_id))
            self.devManager.application_get(app_id=application_id)
            self.devManager.application_list()
            self.devManager.application_delete(app_id=application_id)
            self.devManager.application_list()
        else:
            print(str("Creation Error"))

    def test_subscriptions(self):  # Need WSO2 server to test this
        self.devManager.authentify()
        names    = self.devManager.application_list(names=True)
        print(str(names))
        versions = self.devManager.api_list(names_versions=True)
        print(str(versions))
        self.devManager.unsubscribe(api_name="3gpp-traffic-influence/1.1.2", app_name="TestQosApp")
        self.devManager.subscribe(api_name="3gpp-traffic-influence/1.1.2", app_name="TestQosApp", policy="Unlimited")
        self.devManager.subscription_list(applicationId="dfe79a3e-b042-434f-8db3-b96289e37331")
        data = self.devManager.application_generate_keys(app_name="TestQosApp")
        if (data) :
            print(data.get("token/accessToken"))
        else:
            print("No token")

    def test_dev_settings(self):  # Need WSO2 server to test this
        self.devManager.authentify()
        settings = self.devManager.settings_get()
        print(str(settings))


# Need DataStore Server to test this
class TestDataStore(unittest.TestCase):

    def setUp(self) -> None:
        self.storeManager = StoreManager()
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def generic_test(self, store : str , new_entry : str):  # Need DataStore server to test this
        store = self.storeManager.getStore(store)
        store.authentify()
        store.list()
        print(str(store.d_data.get("count")))
        print(str(store.d_data.get("list/0")))
        store.create(entity=new_entry)
        if (not store.isError()):
            entry_id = store.d_data.get("id")
            print(str(entry_id))
            store.get(entry_id=entry_id)
            store.list()
            store.delete(entry_id=entry_id)
            store.list()
        else:
            print(str("Creation Error"))

    def test_Categories(self):  # Need DataStore server to test this
        new_entry = """
        {
            "CategoryName": "Finance",
            "CategoryLogo": "CategoryLogo",
            "CategoryDescription": "Finance related APIs"
        }  
        """
        self.generic_test("Categories", new_entry)

    def test_Articles(self):  # Need WSO2 server to test this
        new_entry = """
        { 
          "ArticleName" : "ArticleName",
          "ArticleDescription": "ArticleDescription",
          "ArticlePage": "ArticlePage",
          "ArticleLogo": "ArticleLogo"
          }
        """
        self.generic_test("Articles", new_entry)

    def test_Providers(self):  # Need WSO2 server to test this
        new_entry = """
        { 
          "id" : "id",
          "ProviderName" : "ProviderName",
          "ProviderDescription": "ProviderDescription",
          "Contact": "Contact",
          "WebSite": "WebSite",
          "ProviderIcon": "ProviderIcon",
          "ProviderBigLogo": "ProviderBigLogo"
          }
        """
        self.generic_test("Providers", new_entry)

    def test_Accounts(self):  # Need WSO2 server to test this
        new_entry = """
        { 
          "id" : "id",
          "AccountName" : "AccountName",
          "AccountCreationDate": "AccountCreationDate",
          "AccountDescription": "AccountDescription",
          "AccountState": "AccountState",
          "CompanyName": "CompanyName",
          "Industry": [ 
             { "id" : "id",   
               "IndustryCategory"    : "IndustryCategory" , 
               "IndustryInfo"        : "IndustryInfo" , 
               "IndustryPopularity"  : "IndustryPopularity" , 
               "IndustryLogo"        : "IndustryLogo" 
             } 
          ] ,
          "CompanySize": "CompanySize"
          }
        """
        self.generic_test("Accounts", new_entry)

    def test_loader(self):
        FactoryLoader.factory_loader("factory-dataset.json")

    def test_dumper(self):
        StoreManager.store_back_up()
