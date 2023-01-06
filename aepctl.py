#!/usr/bin/env python3

from typing import Union
import requests
from threading import Thread
import json
import shutil
import glob
import os
import sys
import copy
from termcolor import colored
import getopt
import re
import xmltodict
import urllib3
import unittest
import datetime
import base64
from enum import StrEnum
from typing import List
from pydantic import Field
from pydantic import BaseModel
from rich.console import Console
from rich.markdown import Markdown
import Util as ut
import Util_GUI as utg
from prompt_toolkit import PromptSession
from prompt_toolkit import HTML
from prompt_toolkit.history    import FileHistory
from prompt_toolkit.completion import NestedCompleter
from prompt_toolkit.completion import PathCompleter
# from prompt_toolkit.contrib.completers.system import SystemCompleter
import aepctlui
import eapctlms

###
### Logging
###

import logging
# ut.setup_logging()

# Console Output
logging.basicConfig(format='%(levelname)s:%(name)s:%(message)s', level=logging.INFO)

# File Logs
timestamp = datetime.datetime.now().strftime("%y%m%d-%H%M%S")
logDir    = "."+os.sep+"logs"
logFile   = logDir+os.sep+__name__+"-"+timestamp+".log"
logging.basicConfig(filename=logFile, filemode='w', format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.DEBUG)
logger    = logging.getLogger(__name__)

class AepCtlError(Exception):
    def __init__(self, message=''):
        super().__init__(message)
        logger.error(message)


###
### Globals
###

# HOME : Where the configuration is stored
# WORK : Where the runtime data  is stored
# ROOT : Where the applications and static data are installed

AEPCTL_HOME_DIR      = os.path.expanduser('~') + os.sep + ".aepctl"  # HOME Directory
AEPCTL_WORK_DIR      = os.getcwd()                                   # First Time Set Up
AEPCTL_ROOT_DIR      = os.getcwd()                                   # First Time Set Up
AEPCTL_DIRECTORY     = AEPCTL_ROOT_DIR                               # Value from Configuration File

if (not os.path.exists(AEPCTL_HOME_DIR)):  # pragma: no cover
    ut.safeCreateDir(AEPCTL_HOME_DIR)

if (not os.path.exists(AEPCTL_ROOT_DIR)):  # pragma: no cover
    ut.safeCreateDir(AEPCTL_ROOT_DIR)
    ut.safeCreateDir(AEPCTL_ROOT_DIR + os.sep + "etc")
    ut.safeCreateDir(AEPCTL_ROOT_DIR + os.sep + "data")

CONFIG_DIRECTORY   = AEPCTL_ROOT_DIR + os.sep + "etc"
DATA_DIRECTORY     = AEPCTL_ROOT_DIR + os.sep + "data"
TMP_DIRECTORY      = AEPCTL_ROOT_DIR + os.sep + "tmp"
TEST_DIRECTORY     = AEPCTL_ROOT_DIR + os.sep + "tests"
LOGS_DIRECTORY     = AEPCTL_ROOT_DIR + os.sep + "logs"
SCRIPTS_DIRECTORY  = AEPCTL_ROOT_DIR + os.sep + "scripts"
BACKUP_DIRECTORY   = AEPCTL_ROOT_DIR + os.sep + "backup"
STORES_FILE        = AEPCTL_ROOT_DIR + os.sep + "etc" + os.sep + "stores.json"
CONFIG_FILE        = None
STORE_DIRECTORY    = AEPCTL_WORK_DIR + os.sep + "store"


WSO2_SERVER     = "https://localhost:9443"
CATALOG_SERVER  = "http://localhost:30106"
USERS_SERVER    = "http://localhost:30107"
ANME_SERVER     = "https://localhost:5000"    # "https://anme.pagekite.me"
TMF_SERVER      = "https://localhost:8000"
AEP_SERVER      = "localhost:6000"

AEPCTL_PROMPT = "aepctl"

###
### Configuration
###

def_AEPCTL_Configuration = ut.SuperDict(name="AEPCTL_DefaultConfiguration", data={
    "Description"                  : "Default AEPCTL Configuration",
    "WSO2_SERVER"                  : WSO2_SERVER,
    "WSO2_AUTHORIZATION"           : "YWRtaW46YWRtaW4=",
    "CATALOG_SERVER"               : CATALOG_SERVER,
    "USERS_SERVER"                 : USERS_SERVER,
    "ANME_SERVER"                  : ANME_SERVER,
    "TMF_SERVER"                   : TMF_SERVER,
    "AEP_SERVER"                   : AEP_SERVER,
    "AEPCTL_HOME_DIR"              : AEPCTL_HOME_DIR,
    "AEPCTL_ROOT_DIR"              : AEPCTL_ROOT_DIR,
    "AEPCTL_WORK_DIR"              : AEPCTL_WORK_DIR,
    "BACKUP_DIRECTORY"             : BACKUP_DIRECTORY,
    "STORE_DIRECTORY"              : STORE_DIRECTORY,
    "STORES_FILE"                  : STORES_FILE
})

AEPCTL_Configuration_FileName = AEPCTL_HOME_DIR + os.sep + 'AEPCTL_Configuration.json'
AEPCTL_Configuration = ut.SuperDict()

###
### Rest Services
###


class RestHandler:

    def __init__(self, server=None, service : str = "admin"):
        if (not server) : server = AEPCTL_Configuration.get("WSO2_SERVER")
        self.service       = service
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
            self.rest_request = self.server + '/' + request
        logger.info("REST "+op+" : " + str(self.rest_request))
        self.s_data = None
        self.s_text = None
        self.r_data = None
        self.d_data = None
        self.r_text = None
        if (data):
            if (isinstance(data, dict)):         self.s_data = data
            if (isinstance(data, ut.SuperDict)): self.s_data = data.getAsData()
            if (isinstance(data, str)):
                self.s_data = ut.loadDataContent(data)
                if (not self.s_data):
                    self.s_text = data
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

    def hasData(self, codes : list=[200, 202, 204]):
        if (self.r_code in codes) and (self.d_data) :
            return self.d_data
        return None

    def getData(self): return self.r_data

    def r_get(self, request: str, data=None): return self.handle(request, "GET", data)

    def r_post(self, request: str, data=None): return self.handle(request, "POST", data)

    def r_put(self, request: str, data=None): return self.handle(request, "PUT", data)

    def r_delete(self, request: str, data=None): return self.handle(request, "DELETE", data)

    def r_patch(self, request: str, data=None): return self.handle(request, "PATCH", data)

    def r_options(self, request: str, data=None): return self.handle(request, "OPTIONS", data)

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
            endpoint = re.sub("ies$", "ys", endpoint)
            return AEPCTL_Configuration.get("USERS_SERVER") + "/nef-application-user-profile-service/22-03/" + "datastore" + "/" + re.sub("^/", "", endpoint) + ("/" + entry if (entry) else "")
        if (service == "datastore") or (service == "catalog"):
            endpoint = re.sub("ies$", "ys", endpoint)
            return AEPCTL_Configuration.get("CATALOG_SERVER") + "/nef-services-catalog-service/22-03/" + "datastore" + "/" + re.sub("^/", "", endpoint) + ("/" + entry if (entry) else "")
        if (service == "subscription"):  # Typo subsciption => subscription
            return self.server + "/nef-api-subsciption-service/22-03/" + re.sub("^/", "", endpoint) + ("/" + entry if (entry) else "")
        if (service == "admin") or (service == "wso2"):
            return self.server + "/api/am/"+"admin"+"/v2/" + re.sub("^/", "", endpoint) + ("/" + entry if (entry) else "")
        return self.server + "/api/am/"+service+"/v2/" + re.sub("^/", "", endpoint) + ("/" + entry if (entry) else "")

    def authentify(self):
        if (self.authentified) : return
        if (self.service.lower() not in ["admin", "wso2"]) :
            self.authentified = True  # No auth on DataStores for now
            return

        # WS02 REST Authentication
        authorization = AEPCTL_Configuration.get("WSO2_AUTHORIZATION")

        try:
            headers = {
                'Authorization' : 'Basic ' + authorization,
                'Content-Type'  : 'application/json',
            }
            data = {
                  "callbackUrl" : "www.google.lk",
                  "clientName"  : "rest_api_publisher",
                  "owner"       : "admin",
                  "grantType"   : "client_credentials password refresh_token",
                  "saasApp"     : True
                  }

            url = self.server + '/client-registration/v0.17/register'
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

            url = self.server + '/oauth2/token'
            response = requests.post(url, headers=headers, data=data, verify=False)
            dict_response = json.loads(response.text)
            # print(str(json.dumps(dict_response, indent=2)))
            self.access_Token   = str(dict_response["access_token"])
            self.refresh_Token  = str(dict_response["refresh_token"])
            self.token_Type     = str(dict_response["token_type"])
            self.authentified   = True
        except Exception as ex:
            self.r_code = 400
            self.r_text = str(ex).replace("\\n", "\n")
            logger.exception("Exception AUTH Operation : " + self.op + "/n" + self.r_text)
            self.completed()
            raise ex

    def handle_request(self, operation : str = "get", endpoint : str = "apis", entry : str = None, payload=None, files=None, service : str = None) -> Union[str, None]:
        try:
            if (not self.authentified):
                self.authentify()
        except Exception as ex:
            self.r_code = 400
            self.r_text = str(ex).replace("\\n", "\n")
            logger.exception("Exception AUTH Operation : " + self.op + "/n" + self.r_text)
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
        if (not (self.op in ["GET", "LIST", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])):  # pragma: no cover
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
            if (isinstance(payload, ut.SuperDict)): self.s_data = payload.clean().getAsData()
            if (isinstance(payload, str)):          self.s_text = payload
        if (self.s_data):
            self.s_text = json.dumps(self.s_data)
        # payload = None
        if (payload):
            if (isinstance(payload, dict)):         payload  = json.dumps(payload)
            if (isinstance(payload, ut.SuperDict)): payload  = json.dumps(payload.clean().getAsData())
            if (isinstance(payload, str)):          payload  = ut.loadDataContent(payload)
            payload    = ut.to_json(payload)
        logger.info("Rest Payload : "+str(payload))
        self.rest_response = None
        try:
            self.rest_headers = self.headers(files=files)
            if (operation.upper() == "GET"):
                self.rest_request = self.url(endpoint, entry, service=service)
                logger.info("REST " + self.op + " : " + self.rest_request)
                # self.rest_response = requests.get(self.rest_request,    headers=self.rest_headers, data=payload, files=files, verify=False)
                self.rest_response = requests.get(self.rest_request,    headers=self.rest_headers, files=files, verify=False, data=payload)
            elif (operation.upper() == "LIST"):
                self.rest_request = self.url(endpoint, service=service)
                logger.info("REST " + self.op + " : " + self.rest_request)
                self.rest_response = requests.get(self.rest_request,    headers=self.rest_headers, files=files, verify=False, data=payload)
            elif (operation.upper() == "POST"):
                self.rest_request = self.url(endpoint, service=service)
                logger.info("REST " + self.op + " : " + self.rest_request)
                self.rest_response = requests.post(self.rest_request,   headers=self.rest_headers, files=files, verify=False, data=payload)
            elif (operation.upper() == "DELETE"):
                self.rest_request = self.url(endpoint, entry, service=service)
                logger.info("REST " + self.op + " : " + self.rest_request)
                self.rest_response = requests.delete(self.rest_request, headers=self.rest_headers, files=files, verify=False, data=payload)
            elif (operation.upper() == "PUT"):
                self.rest_request = self.url(endpoint, entry, service=service)
                logger.info("REST " + self.op + " : " + self.rest_request)
                self.rest_response = requests.put(self.rest_request,    headers=self.rest_headers, files=files, verify=False, data=payload)
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

###
### DataStore
###


class DataStoreInterface():
    """ Abstract DataStore Class """

    def __init__(self, entity_type="articles", name_att=None, desc_att=None, id_att=None, service=None, schema=None):
        self.errortxt    = None
        self.store_type  = "file" if isinstance(self, FileDataStore) else "rest"
        self.entity_type = entity_type
        self.name_att    = name_att if (name_att) else StoreManager().get_name_att(entity_type)
        self.desc_att    = desc_att if (desc_att) else StoreManager().get_desc_att(entity_type)
        self.id_att      = id_att   if (id_att)   else StoreManager().get_id_att(entity_type)
        self.service     = service  if (service)  else StoreManager().store_get_service(entity_type)
        self.schema      = schema   if (schema)   else StoreManager().store_get_schema(entity_type)

    def error(self, error_text : Union [str, None] = "", log : bool = True) -> Union [str, None]:
        """ Set or Reset error, returns error """
        if (error_text == ""): return self.errortxt
        if (not error_text): self.errortxt = None
        if ((error_text) and (log)): logger.error(error_text)
        self.errortxt = error_text
        return self.errortxt

    def isError(self) -> bool:
        return (self.error() != None)

    def resetError(self):
        self.error(None)

    def setError(self, error_text : str, log : bool = True):
        self.error(error_text, log)

    def getError(self) -> str:
        return self.error()

    def check(self, entity : Union[str, dict]) -> Union [dict, None]:
        """ Check is entity is compliant to schema
        :returns None or Valid dict entity
        """
        self.resetError()
        pEntity = entity
        if (isinstance(entity, str)) :
            entity = ut.loadDataContent(entity)
            if (not entity):
                self.setError("Invalid JSON or YAML Format : "+str(pEntity))
                return None
        if (not isinstance(entity, dict)) :
            self.setError("Invalid Dict Format : "+str(entity))
            return None
        if (StoreManager.get_schema(self.entity_type)):
            self.setError(StoreManager.check_schema(entity, self.entity_type))
        return None if (self.error()) else entity

    def list(self, names : bool = False, ids : bool = False, count : bool = False) -> Union [list, None, int]:
        pass   # pragma: no cover

    def _list(self, entity_list : list, names: bool = False, ids: bool = False, count: bool = False) -> Union[list, None, int]:
        if (not entity_list): return list()
        if ("list" in entity_list): entity_list = entity_list["list"]
        if (count): return len(entity_list)
        if (names): return [entity[self.name_att] for entity in entity_list]
        if (ids):   return [entity[self.id_att]   for entity in entity_list]
        return entity_list

    def entryByIdName(self, idName : str) -> Union[None, dict]:
        self.resetError()
        for entry in self.list():
            if ((self.id_att   in entry) and (entry[self.id_att]   == idName)): return entry
            if ((self.name_att in entry) and (entry[self.name_att] == idName)): return entry
        self.setError("No such entry : " + str(idName), log=False)
        return None

    def idName(self, idName : str = None, name: str = None, identifier: str = None) -> str:
        if (idName)     : value = idName
        if (name)       : value = name
        if (identifier) : value = identifier
        return value

    def idByName(self, idName : str) -> Union[None, dict]:
        entry = self.entryByIdName(idName=idName)
        return None if ((not entry) or (self.id_att not in entry)) else entry[self.id_att]

    def nameById(self, idName : str) -> Union[str, None]:
        entry = self.entryByIdName(idName=idName)
        return None if ((not entry) or (self.name_att not in entry)) else entry[self.name_att]

    def descByIdname(self, idName : str) -> Union[str, None]:
        entry = self.entryByIdName(idName=idName)
        return None if ((not entry) or (self.desc_att not in entry)) else entry[self.desc_att]

    def exist(self, idName : str) -> bool:
        return True if self.entryByIdName(idName=idName) else False

    def get(self, idName : str = None , name : str = None, identifier : str = None) -> Union [dict, None]:
        """ Return entity by fetching all list
        """
        return self.entryByIdName(self.idName(idName, name, identifier))

    def create(self, entity : Union[str, dict], backup : bool = True) -> Union [dict, None]:
        """ Checking Data Structure to be created vs schema
        and allocating UUID Identifier, plus store backup
        """
        entity = self.check(entity=entity)
        if (not entity): return None
        if (self.id_att not in entity): entity[self.id_att] = ut.uuid()
        if (backup): StoreManager.store_back_up(service=self.store_type)
        return entity

    def update(self, entity : Union[str, dict], backup : bool = True) -> Union [dict, None]:
        """ Checking Data Structure to be updated vs schema
        and allocating UUID Identifier, plus store backup
        """
        entity = self.check(entity=entity)
        if (not entity): return None
        if (self.id_att not in entity): entity[self.id_att] = ut.uuid()
        if (backup): StoreManager.store_back_up(service=self.store_type)
        return entity

    def save(self, entity : Union[str, dict], backup : bool = True) -> Union [dict, None]:
        if ((self.exist((entity[self.id_att]))) or (self.exist((entity[self.name_att])))):
            return self.update(entity=entity, backup=backup)
        else:
            return self.create(entity=entity, backup=backup)

    def delete(self, idName : str = None , name : str = None, identifier : str = None, backup : bool = True) -> Union [dict, None]:
        idName = self.idName(idName, name, identifier)
        entry  = self.get(idName=idName)
        if (not entry) :
            self.setError("No such entry : " + str(idName))
            return None
        if (backup): StoreManager.store_back_up(service=self.store_type)
        return entry

    def deleteAll(self, backup : bool = True) -> Union [list, None]:
        self.resetError()
        all_errors  = ""
        del_entries = list()
        if (backup): StoreManager.store_back_up(service=self.store_type)
        for entry_id in self.list(ids=True) :
            entry = self.delete(identifier=entry_id, backup=False)
            if (entry): del_entries.append(entry)
            if (self.isError()): all_errors = all_errors + "\n" + self.getError()
        if (all_errors != "") : self.setError(all_errors)
        logger.info(self.service + " Store Deleted all : ["+self.entity_type+"]")
        return del_entries

    def dumpAll(self, filename : str = None, directory : str = BACKUP_DIRECTORY) -> dict:
        self.resetError()
        entries = self.list()
        store = dict()
        store["desc_att"]  = self.desc_att
        store["name_att"]  = self.name_att
        store["service"]   = self.service
        store["schema"]    = self.schema
        store["entity"]    = self.entity_type
        store["count"]     = len(entries) if (entries) else 0
        store["timestamp"] = ut.timestamp()
        store["entries"]   = entries if (entries) else []
        if (not ut.safeDirExist(directory)):  # pragma: no cover
            logger.info("Creating Directory : " + directory)
            ut.safeCreateDir(directory)
        logger.info("BackUp Dir : " + directory)
        if (not filename):
            filename = directory + os.sep + self.entity_type + "_dump.json"
        ut.saveJsonFile(store, filename)
        logger.info(str(self.service)+" [" + self.entity_type + "] Store saved in file : " + filename)
        return store

    def backup(self) -> dict:
        store    = "file" if (isinstance(self, FileDataStore)) else "rest"
        filename = BACKUP_DIRECTORY + os.sep + ut.timestamp() + "_" + store + "_" + self.service + "_" + self.entity_type + "_backup.json"
        return self.dumpAll(filename, BACKUP_DIRECTORY)

    def storeFile(self, filename : str = None, directory : str = None) -> dict:
        """ Dump Data Store Entries in File """
        global STORE_DIRECTORY
        if (not directory) : directory = STORE_DIRECTORY
        return self.dumpAll(filename, directory)

    def loadFile(self, filename : str = None, directory : str = None, save : bool = True) -> list:
        """ Load Entries from File
        Optionally Save in Data Store
        """
        global STORE_DIRECTORY
        self.resetError()
        if (not directory) : directory = STORE_DIRECTORY
        if (not ut.safeDirExist(directory)):
            logger.info("Creating Directory : " + directory)  # pragma: no cover
            ut.safeCreateDir(directory)                       # pragma: no cover
        if (not filename):
            filename = directory + os.sep + self.entity_type + "_dump.json"
        if (not ut.safeFileExist(filename)):
            logger.info("File not found : " + str(filename))  # pragma: no cover
            logger.info("Creating File  : " + str(filename))  # pragma: no cover
            self.storeFile()                                 # pragma: no cover
        logger.info("Loading File       : " + filename)
        data = ut.loadDataFile(filename)
        if (not data):
            logger.info("Invalid Data Format : " + filename)  # pragma: no cover
            return None                                       # pragma: no cover
        data = StoreManager.check_store_file(data, factory=True)
        if (not data):
            logger.info("Invalid Data Format : " + filename)  # pragma: no cover
            return None                                       # pragma: no cover
        if (save) :
            self.backup()
            for entry in data["entries"]:
                self.save(entity=entry, backup=False)
        return data["entries"]


class FileDataStore(DataStoreInterface):

    def __init__(self, directory=None, entity_type="articles", name_att=None, desc_att=None, id_att=None, service=None, schema=None):
        global STORE_DIRECTORY
        if (not directory) : directory = STORE_DIRECTORY
        DataStoreInterface.__init__(self, entity_type=entity_type, name_att=name_att, desc_att=desc_att, id_att=id_att, service=service, schema=schema)
        self.cache       = self.loadFile(directory=directory, save=False)

    def create(self, entity : Union[str, dict], backup : bool = True) -> Union [dict, None]:
        entry = super(FileDataStore, self).create(entity=entity, backup=backup)
        if ((self.isError()) or (not entry)): return None
        self.cache.append(entry)
        self.cache = sorted(self.cache, key=lambda d: d[self.name_att])
        self.storeFile()
        return entry

    def list(self, names : bool = False, ids : bool = False, count : bool = False) -> Union [list, None, int]:
        self.resetError()
        entries = self.cache
        if (names) :
            names = []
            for entry in entries:
                names.append(entry[self.name_att])
            return names
        if (ids) :
            ids = []
            for entry in entries:
                ids.append(entry[self.id_att])
            return ids
        if (count) :
            return len(entries)
        if (entries == None): return list()
        self.cache = sorted(entries, key=lambda d: d[self.name_att])
        return entries

    def get(self, idName : str = None , name : str = None, identifier : str = None) -> Union [dict, None, str]:
        idName = self.idName(idName, name, identifier)
        entry = super(FileDataStore, self).get(idName=idName, name=name, identifier=identifier)
        if (entry): return entry
        self.setError("No such entry : " + str(idName))
        return None

    def update(self, entity : Union[str, dict], backup : bool = True) -> Union [dict, None]:
        super(FileDataStore, self).update(entity=entity, backup=backup)
        if (self.isError()): return None
        new_entity = entity
        if (self.id_att in entity):
            entity_id  = entity[self.id_att]
            old_entity = self.delete(identifier=entity_id, backup=backup)
            if (old_entity): new_entity = old_entity | entity
        self.cache.append(new_entity)
        self.cache = sorted(self.cache, key=lambda d: d[self.name_att])
        self.storeFile()
        return new_entity

    def delete(self, idName : str = None , name : str = None, identifier : str = None, backup : bool = True) -> Union [dict, None]:
        entry = super(FileDataStore, self).delete(idName=idName, name=name, identifier=identifier, backup=backup)
        if (self.isError()): return None
        if (not entry): return None
        if (self.id_att not in entry): return None
        filtered_list = [d for d in self.cache if d[self.id_att] != entry[self.id_att]]
        self.cache = filtered_list
        self.cache = sorted(self.cache, key=lambda d: d[self.name_att])
        self.storeFile()
        return entry

    def copy_ds_to_fs(self, reset=False) -> list:
        self.resetError()
        server = RestDataStore(entity_type=self.entity_type, name_att=self.name_att, desc_att=self.desc_att, id_att=self.id_att, service=self.service)
        if (reset) :
            self.deleteAll(backup=True)
        for entry in server.list():
            self.update(entry)
        self.cache = sorted(self.cache, key=lambda d: d[self.name_att])
        return self.cache

    def copy_fs_to_ds(self, reset=False) -> list:
        self.resetError()
        server = RestDataStore(entity_type=self.entity_type, name_att=self.name_att, desc_att=self.desc_att, id_att=self.id_att, service=self.service)
        if (reset) :
            server.deleteAll(backup=True)
        for entry in self.cache:
            server.update(entry)
        return server.list()


class RestDataStore(DataStoreInterface, RestHandler):

    def __init__(self, server=CATALOG_SERVER, entity_type="articles", name_att=None, desc_att=None, id_att=None, service=None, schema=None):
        DataStoreInterface.__init__(self, entity_type=entity_type, name_att=name_att, desc_att=desc_att, id_att=id_att, service=service, schema=schema)
        RestHandler.__init__(self, server, service=service)
        self.authentify()

    def create(self, entity : Union[str, dict], backup : bool = True) -> Union [dict, None]:
        entity = super(RestDataStore, self).create(entity=entity, backup=backup)
        if (self.isError()): return None
        self.handle_request("POST", self.entity_type, payload=ut.to_json(entity), service=self.service)
        if (not self.hasData()) :
            self.setError("POST ["+self.entity_type+"] : No Data from Server\n"+str(self._getError()))
            return None
        return ut.loadDataContent(self.r_text)

    def list(self, names : bool = False, ids : bool = False, count : bool = False) -> Union [list, None, int]:
        self.resetError()
        self.handle_request("LIST", self.entity_type, service=self.service)
        if (self.isError()) :     return None
        if (not self.hasData()) :
            self.setError("LIST ["+self.entity_type+"] : No Data from Server\n"+str(self._getError()))
            return list()
        entry_list = sorted(self.d_data.getAsData()["list"], key=lambda d: d[self.name_att])
        if (names) :
            names = []
            for entry in entry_list:
                names.append(entry[self.name_att])
            return names
        if (ids) :
            ids = []
            for entry in entry_list:
                ids.append(entry[self.id_att])
            return ids
        if (count) :
            return len(entry_list)
        return entry_list

    def get(self, idName : str = None , name : str = None, identifier : str = None) -> Union [dict, None]:
        entity_id = super(RestDataStore, self).get(idName=idName, name=name, identifier=identifier)
        if (not entity_id): return None
        self.handle_request("GET", self.entity_type, entry=entity_id, service=self.service)
        if (not self.hasData()) :
            self.setError("GET ["+self.entity_type+"/"+entity_id+"] : No Data from Server\n"+str(self._getError()))
            return None
        logger.info("Rest Store Get : ["+self.entity_type+"/"+entity_id+"]\n"+self.r_text)
        return ut.loadDataContent(self.r_text)

    def update(self, entity : Union[str, dict], backup : bool = True) -> Union [dict, None]:
        super(RestDataStore, self).update(entity=entity, backup=backup)
        if (self.isError()): return None
        entity_id  = entity[self.id_att]
        if (not self.exist(entity_id)):
            return self.create(entity=entity, backup=backup)
        new_entity = entity
        if (self.id_att in new_entity):
            old_entity = self.get(identifier=entity[self.id_att])
            if (old_entity): new_entity = old_entity | entity
        new_entity.pop(self.id_att)   # Else Schema validation fails
        self.handle_request("PUT", self.entity_type, entry=entity_id, payload=new_entity, service=self.service)
        if (not self.hasData()) :
            self.setError("PUT ["+self.entity_type+"/"+entity_id+"] : No Data from Server\n"+str(self._getError()))
            return None
        logger.info("Rest Store Update : ["+self.entity_type+"/"+entity_id+"]\n"+self.r_text)
        return ut.loadDataContent(self.r_text)

    def delete(self, idName : str = None , name : str = None, identifier : str = None, backup : bool = True) -> Union [dict, None]:
        entry = super(RestDataStore, self).delete(idName=idName, name=name, identifier=identifier, backup=backup)
        if (self.isError()): return None
        if (not entry): return None
        self.handle_request("DELETE", self.entity_type, entry=entry[self.id_att], service=self.service)
        if (self.r_code != 204) and (not self.hasData()) :
            self.setError("DELETE ["+self.entity_type+"/"+entry[self.id_att]+"] : No Data from Server\n"+str(self._getError()))
            return None
        logger.info("Rest Store Deleted : ["+self.entity_type+"/"+entry[self.id_att]+"]\n"+self.r_text)
        return entry


class AnmeDataStore(DataStoreInterface, RestHandler):

    def __init__(self, server=None, entity_type="articles", name_att=None, desc_att=None, id_att=None, service=None, schema=None):
        if (not server): server = AEPCTL_Configuration.get("ANME_SERVER")
        self.server_entity_type = entity_type.replace("ies", "ys")
        DataStoreInterface.__init__(self, entity_type=entity_type, name_att=name_att, desc_att=desc_att, id_att=id_att, service=service, schema=schema)
        RestHandler.__init__(self, server, service=service)
        # self.authentify()

    def create(self, entity : Union[str, dict], backup : bool = True) -> Union [dict, None]:
        entity = super(AnmeDataStore, self).create(entity=entity, backup=backup)
        if (self.isError()): return None
        id = entity[self.id_att]
        req = "filestore/" + self.server_entity_type + "/" + id
        self.handle(req , "POST", data=ut.to_json(entity))
        # self.handle_request("POST", self.server_entity_type, payload=ut.to_json(entity), service=self.service)
        if (not self.hasData()) :
            self.setError("POST ["+self.server_entity_type+"] : No Data from Server\n"+str(self._getError()))
            return None
        new_entity = self.get(identifier=id)
        if ("VersionControl" in new_entity) : del new_entity["VersionControl"]
        return new_entity

    def list(self, names : bool = False, ids : bool = False, count : bool = False) -> Union [list, None, int]:
        self.resetError()
        req = "filestore/" + self.server_entity_type
        self.handle(req , "GET")
        # self.handle_request("LIST", self.server_entity_type, service=self.service)
        if (self.isError()) :     return None
        if (not self.hasData()) :
            self.setError("LIST ["+self.server_entity_type+"] : No Data from Server\n"+str(self._getError()))
            return list()
        ids_list = self.d_data.getAsData()[self.server_entity_type]
        if (ids)   : return ids_list
        if (count) : return len(ids_list)
        entry_list = list()
        for entry_id in ids_list:
            entry = self.get(identifier=entry_id)
            entry_list.append(entry)
        print(str(entry_list))
        print(str(self.name_att))
        entry_list = [o for o in entry_list if o]
        entry_list = sorted(entry_list, key=lambda d: d[self.name_att])
        if (names) :
            names = []
            for entry in entry_list:
                names.append(entry[self.name_att])
            return names
        if (ids) :
            ids = []
            for entry in entry_list:
                ids.append(entry[self.id_att])
            return ids
        if (count) :
            return len(entry_list)
        return entry_list

    def get(self, idName : str = None , name : str = None, identifier : str = None) -> Union [dict, None]:
        entity_id = super(AnmeDataStore, self).get(idName=idName, name=name, identifier=identifier)
        if (not entity_id): return None
        req = "filestore/" + self.server_entity_type + "/" + entity_id
        self.handle(req , "GET")
        # self.handle_request("GET", self.server_entity_type, entry=entity_id, service=self.service)
        if (not self.hasData()) :
            self.setError("GET ["+self.server_entity_type+"/"+entity_id+"] : No Data from Server\n"+str(self._getError()))
            return None
        logger.info("Rest Store Get : ["+self.server_entity_type+"/"+entity_id+"]\n"+self.r_text)
        new_entity = ut.loadDataContent(self.r_text)
        if ("VersionControl" in new_entity) : del new_entity["VersionControl"]
        return new_entity

    def update(self, entity : Union[str, dict], backup : bool = True) -> Union [dict, None]:
        super(AnmeDataStore, self).update(entity=entity, backup=backup)
        if (self.isError()): return None
        entity_id  = entity[self.id_att]
        if (not self.exist(entity_id)):
            return self.create(entity=entity, backup=backup)
        new_entity = entity
        if (self.id_att in new_entity):
            old_entity = self.get(identifier=entity[self.id_att])
            if (old_entity): new_entity = old_entity | entity
        req = "filestore/" + self.server_entity_type + "/" + new_entity[self.id_att]
        # new_entity.pop(self.id_att)   # Else Schema validation fails
        self.handle(req , "PUT", data=ut.to_json(new_entity))
        # self.handle_request("PUT", self.server_entity_type, entry=entity_id, payload=new_entity, service=self.service)
        if (not self.hasData()) :
            self.setError("PUT ["+self.server_entity_type+"/"+entity_id+"] : No Data from Server\n"+str(self._getError()))
            return None
        logger.info("Rest Store Update : ["+self.server_entity_type+"/"+entity_id+"]\n"+self.r_text)
        new_entity = self.get(identifier=entity_id)
        if (not self.hasData()) :
            self.setError("POST ["+self.server_entity_type+"] : No Data from Server\n"+str(self._getError()))
            return None
        if ("VersionControl" in new_entity) : del new_entity["VersionControl"]
        return new_entity

    def delete(self, idName : str = None , name : str = None, identifier : str = None, backup : bool = True) -> Union [dict, None]:
        entry = super(AnmeDataStore, self).delete(idName=idName, name=name, identifier=identifier, backup=backup)
        if (self.isError()): return None
        if (not entry): return None
        req = "filestore/" + self.server_entity_type + "/" + entry[self.id_att]
        self.handle(req , "DELETE")
        # self.handle_request("DELETE", self.server_entity_type, entry=entry[self.id_att], service=self.service)
        if (self.r_code != 204) and (not self.hasData()) :
            self.setError("DELETE ["+self.server_entity_type+"/"+entry[self.id_att]+"] : No Data from Server\n"+str(self._getError()))
            return None
        logger.info("Rest Store Deleted : ["+self.server_entity_type+"/"+entry[self.id_att]+"]\n"+self.r_text)
        return entry

###
### Wso2
###

"""
{
    "name" : "name",
    "credential": "credential",
    "role": (apiCreator, apiConsumer, apiAdmin, apiMonitoring) ,
    "requirePasswordChange": "requirePasswordChange"
}
"""

apiRoles         = [ "apiCreator", "apiConsumer", "apiAdmin", "apiMonitoring"]
# apiCreatorRoles  = [ 'Internal/everyone', 'Internal/creator', 'Application/apim_publisher', 'Internal/publisher', 'Application/rest_api_publisher']
apiCreatorRoles  = [ 'Internal/everyone', 'Internal/creator',  'Application/apim_publisher', 'Internal/publisher']
apiConsumerRoles = [ 'Internal/everyone', 'Application/apim_devportal' ]
apiAdminRoles    = [ 'Internal/everyone', 'admin', 'Internal/devops', 'Internal/analytics' ]
apiMonitoring    = [ 'Internal/everyone', 'Internal/analytics']


class Wso2Manager(RestHandler):

    def __init__(self, ws_server=None):
        if (not ws_server) : ws_server = AEPCTL_Configuration.get("WSO2_SERVER")
        super().__init__(ws_server)

    @staticmethod
    def browser(what: str = "publisher", w_server: str = None, openURL: bool = True):
        if (not w_server):
            w_server = AEPCTL_Configuration.get("WSO2_SERVER")
        if (what.lower() in ["publisher", "apim"]):
            if (openURL): ut.open_browser(w_server + "/publisher")
            return "API Publisher Portal : " + w_server + "/publisher"
        if (what.lower() in ["devportal", "dev", "portal"]):
            if (openURL): ut.open_browser(w_server + "/devportal")
            return "WSO2 API Developer Portal : " + w_server + "/devportal"
        if (what.lower() in ["mgt", "console", "carbon"]):
            if (openURL): ut.open_browser(w_server + "/carbon/")
            return "WSO2 Mgt Console Portal : " + w_server + "/carbon/"
        return

    def getData(self, operation : str = "get", endpoint : str = "apis", service : str = None) -> dict:
        self.handle_request(operation=operation, endpoint=endpoint, service=service)
        return self.d_data if (self.d_data) else {}

    def getSettings(self):
        settings = ut.SuperDict()
        settings["id"]   = "DEVELOPER_PORTAL"
        settings["name"] = "dev"
        settings["description"] = "Developer Portal Settings"

        settings["settings"]       = self.getData("GET", "settings", "admin")
        settings["alert-types"]    = self.getData("GET", "alert-types", "admin")
        settings["key-managers"]   = self.getData("GET", "key-managers", "admin")
        settings["environments"]   = self.getData("GET", "environments", "admin")
        settings["api-categories"] = self.getData("GET", "api-categories", "admin")
        settings["bot-detection-data"] = self.getData("GET", "bot-detection-data", "admin")

        # Policy Types : application / custom / advanced / deny-policies / mediation / subscription
        settings["throttling/policies/application"]   = self.getData("GET", "throttling/policies/application", "admin")
        settings["throttling/policies/custom"]        = self.getData("GET", "throttling/policies/custom", "admin")
        settings["throttling/policies/advanced"]      = self.getData("GET", "throttling/policies/advanced", "admin")
        settings["throttling/policies/deny-policies"] = self.getData("GET", "throttling/policies/deny-policies", "admin")
        settings["throttling/policies/subscription"]  = self.getData("GET", "throttling/policies/subscription", "admin")
        settings["policies/mediation"]                = self.getData("GET", "policies/mediation", "admin")

        settings["publisher/apis"]          = self.getData("LIST", "apis", "publisher")
        settings["publisher/tenants"]       = self.getData("LIST", "tenants?state=active", "publisher")
        settings["publisher/subscriptions"] = self.getData("LIST", "subscriptions", "publisher")
        settings["publisher/api-products"]  = self.getData("LIST", "api-products", "publisher")
        settings["publisher/settings"]      = self.getData("LIST", "settings", "publisher")
        settings["publisher/mediation-policies"] = self.getData("LIST", "mediation-policies", "publisher")

        return settings


class Wso2UsersManager(DataStoreInterface):
    """ User Management is via SOAP on WS02 4.0.0 """

    def __init__(self, authorization=None, server=None, entity_type="WS_Users"):
        DataStoreInterface.__init__(self, entity_type=entity_type)
        if (not server)        : server        = AEPCTL_Configuration.get("WSO2_SERVER")
        if (not authorization) : authorization = AEPCTL_Configuration.get("WSO2_AUTHORIZATION")
        self.server                  = server
        self.authorization           = authorization
        self.last_operation          = "Nope"
        self.last_operation_code     = 200
        self.last_operation_error    = ""
        self.last_operation_details  = ""
        self.last_operation_response = ""
        self.last_operation_headers  = ""
        self.last_operation_payload  = ""
        self.last_operation_text     = ""

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

        url = self.server + '/services/RemoteUserStoreManagerService.RemoteUserStoreManagerServiceHttpsSoap11Endpoint'
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

        if (self.last_operation_code >= 299):
            logger.error(str(self.last_operation_code)+" : The request has returned en error.")
            errorText = "Code     : " + str(self.last_operation_code) + "\n"
            errorText = errorText + "Response : " + str(self.last_operation_response) + "\n"
            errorText = errorText + "Fault    : " + str(self.last_operation_error) + "\n"
            errorText = errorText + "Details  : " + str(self.last_operation_details) + "\n"
            self.setError(errorText)
            return self.last_operation_response

        if (response.status_code == 200):
            logger.info("200 : The request has returned values.")
            if ("ns:listUsersResponse" in dict_resp["soapenv:Envelope"]["soapenv:Body"]):
                self.last_operation_response = str(dict_resp["soapenv:Envelope"]["soapenv:Body"]["ns:listUsersResponse"]["ns:return"])
            if ("ns:isExistingUserResponse" in dict_resp["soapenv:Envelope"]["soapenv:Body"]):
                self.last_operation_response = str(dict_resp["soapenv:Envelope"]["soapenv:Body"]["ns:isExistingUserResponse"]["ns:return"])
            if ("ns:getRoleListOfUserResponse" in dict_resp["soapenv:Envelope"]["soapenv:Body"]):
                self.last_operation_response = str(dict_resp["soapenv:Envelope"]["soapenv:Body"]["ns:getRoleListOfUserResponse"]["ns:return"])
            logger.info(str(self.last_operation_response))
            return self.last_operation_response

        if (response.status_code == 202):
            logger.info("202 : The request has been accepted for processing.")
            return "Success 202"

        return self.last_operation_response

    def settings_get(self) -> dict:
        settings = ut.SuperDict(name="ADMIN SETTINGS")
        settings["id"]   = "ADMIN"
        settings["name"] = "wso2"
        settings["description"]   = "Users Admin Settings"
        settings["authorization"] = self.authorization
        settings["WSO2_SERVER"]   = self.server
        settings.clean()
        return settings.getAsData()

    def get_user(self, userName: Union[str, dict]) -> Union[None, dict]:
        if (isinstance(userName, dict)):
            userName = userName["name"] if ("name" in userName) else "NameError"
        if (not self.is_user(userName)) : return None
        wso2_roles = self.get_user_roles(userName)
        user_role = self.get_role(userName)
        user =  { "name" : userName, "role" : user_role, "wso2_roles" : wso2_roles }
        logger.info("Get User : "+userName + "\n" + ut.to_json(user))
        return user

    def delete_user(self, userName: Union[str, dict]) -> Union[None, dict]:
        if (isinstance(userName, dict)):
            userName = userName["name"] if ("name" in userName) else "NameError"
        user = self.get_user(userName)
        if (not user) : return None
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
        res = self.handle_request(headers, payload_xml)
        if (self.isError()):  # pragma: no cover
            logger.error("Delete User Error : " + "\n" + self.getError())
            return None
        logger.info("Delete User : "+userName + "\n" + str(res))
        return user

    def is_user(self, userName: str) -> Union[None, bool]:
        if (isinstance(userName, dict)):
            userName   = userName["name"]       if ("name" in userName) else "NameError"
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
        res = self.handle_request(headers, payload_xml)
        if (self.isError()):  # pragma: no cover
            logger.error("Is User Error : " + "\n" + self.getError())
            return None
        logger.info("Is User : "+userName + "\n" + str(res))
        if (res.lower() == "false") : return False
        if (res.lower() == "true")  : return True
        return False  # pragma: no cover

    def add_user(self, userName: Union[str, dict], credential: str = None, role : str = None, requirePasswordChange : bool = False) -> Union[None, dict]:
        self.last_operation = "Add User : " + str(userName)
        if (isinstance(userName, dict)):
            user = copy.deepcopy(userName)
            userName   = user["name"] if ("name" in user) else "NameError"
            credential = user["credential"] if ("credential" in user) else (str(credential) if credential else userName)
            role       = user["role"]       if ("role" in user) else str(role)
            requirePasswordChange = user["requirePasswordChange"] if ("requirePasswordChange" in user) else requirePasswordChange
        if (not credential) : credential = userName
        roleList = ""
        if (role.lower() in ["creator", "apicreator", "publisher", "apipublisher"] ) :
            roleList = str(apiCreatorRoles)
        elif (role.lower() in ["monitoring", "apimonitoring"]) :
            roleList = str(apiMonitoring)
        elif (role.lower() in ["admin", "apiadmin"]) :
            roleList = str(apiAdminRoles + apiConsumerRoles + apiCreatorRoles + apiMonitoring)
        elif (role.lower() in ["consumer", "apiconsumer", "client", "apiclient"]) :
            roleList = str(apiConsumerRoles)
        else :
            self.last_operation_error   = 600
            self.last_operation_error   = "Error"
            self.last_operation_details = "Add User Error - Invalid Role : " + str(role)
            logger.error("Add User Error - Invalid Role : " + str(role))
            return None
        roleList = str(roleList).strip("[").strip("]")
        logger.info("User       : " + str(userName))
        logger.info("Credential : " + str(credential))
        logger.info("RoleList   : " + str(roleList).strip("[").strip("]"))
        logger.info("RequirePasswordChange : " + str(requirePasswordChange))
        ser_roles = ""
        for roles in list(dict.fromkeys(ut.textToList(roleList))):
            ser_roles = ser_roles + "<ser:roleList>"+str(roles)+"</ser:roleList>\n"
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
                 <ser:userName>"""+str(userName)+"""</ser:userName>
                 <!--Optional:-->
                 <ser:credential>"""+str(credential)+"""</ser:credential>
                 <!--Zero or more repetitions:-->
                 <!--<ser:roleList>"""+str(roleList)+"""</ser:roleList>-->
                 """+ser_roles+"""
                 <!--Optional:-->
                 <ser:requirePasswordChange>"""+str(requirePasswordChange)+"""</ser:requirePasswordChange>
              </ser:addUser>
           </soapenv:Body>
        </soapenv:Envelope>
        """
        if (self.is_user(userName)):  # Delete if exists
            self.delete_user(userName)
        res = self.handle_request(headers, payload_xml)
        logger.debug("Add User Error : " + "\n" + str(res))
        if (self.isError()) :  # pragma: no cover
            logger.info("Add User Error : " + "\n" + self.getError())
            return None
        logger.info("Added User : " + "\n" + userName)
        user = self.get_user(userName)
        user["credential"]            = credential
        user["requirePasswordChange"] = requirePasswordChange
        return user

    def list_users(self, names : bool = True) -> Union[None, list]:
        if (names == False):
            users = self.list_users(names=True)
            usersList = list()
            for username in users:
                user = self.get(identifier=username)
                usersList.append(user)
            return usersList
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
        res = self.handle_request(headers, payload_xml)
        if (self.isError()):  # pragma: no cover
            logger.error("List User Error : " + "\n" + self.getError())
            return None
        logger.info("List User : " + "\n" + str(res))
        return ut.textToList(res)

    def get_user_roles(self, userName: str) -> Union[None, list]:
        if (isinstance(userName, dict)):
            userName   = userName["name"]       if ("name" in userName) else "NameError"
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
        res = self.handle_request(headers, payload_xml)
        if (self.isError()):  # pragma: no cover
            logger.error("Get User Error : " + "\n" + self.getError())
            return None
        logger.info("User Roles : "+userName + "\n" + str(res))
        return ut.textToList(res)

    def get_role(self, userName: str) -> Union[None, str]:
        roles = self.get_user_roles(userName)
        if (not roles): return None
        if (ut.isListContainedInList(apiAdminRoles, roles)):     return "apiAdmin"
        if (ut.isListContainedInList(apiMonitoring, roles)):     return "apiMonitoring"
        if (ut.isListContainedInList(apiCreatorRoles, roles)):   return "apiCreator"
        if (ut.isListContainedInList(apiConsumerRoles, roles)):  return "apiConsumer"
        return None  # pragma: no cover

    # Interface functions
    def create(self, entity: Union[str, dict], backup: bool = True) -> Union[dict, None]:
        entity = super().create(entity=entity, backup=backup)
        if (self.isError()): return None
        return self.add_user(entity)

    def list(self, names: bool = False, ids: bool = False, count: bool = False) -> Union[list, None, int]:
        self.resetError()
        users_list = self.list_users(names=False)
        if (self.isError()):  return None
        return self._list(users_list, names=names, ids=ids, count=count)

    def get(self, idName: str = None, name: str = None, identifier: str = None) -> Union[dict, None]:
        entity_id = super().get(idName=idName, name=name, identifier=identifier)
        if (not entity_id): return None
        return self.get_user(entity_id)

    def update(self, entity: Union[str, dict], backup: bool = True) -> Union[dict, None]:
        super(DataStoreInterface, self).update(entity=entity, backup=backup)
        if (self.isError()): return None
        if (backup): self.backup()
        self.delete_user(entity)
        if (self.isError()): return None
        return self.add_user(entity)

    def delete(self, idName: str = None, name: str = None, identifier: str = None, backup: bool = True) -> Union[dict, None]:
        entry = super(DataStoreInterface, self).delete(idName=idName, name=name, identifier=identifier, backup=backup)
        if (self.isError()): return None
        if (backup): self.backup()
        return self.delete_user(entry)


class Wso2CategoriesManager(DataStoreInterface, RestHandler):

    def __init__(self, server=None, entity_type="WS_Categories"):
        DataStoreInterface.__init__(self, entity_type=entity_type)
        RestHandler.__init__(self, server, service=StoreManager().store_get_service(entity_type))

    def category_create(self, category : str, description : str = None):
        if (description):
            cat = { "name" : category , "description" : description }
            category = ut.to_json(cat)
        else :
            category = category
            cat = ut.loadDataContent(category)
        if (self.category_get(cat["name"])):
            ident = self.category_get_id(cat["name"])
            self.handle_request("PUT", "api-categories", payload=category, entry=ident)
        else:
            self.handle_request("POST", "api-categories", payload=category)
        if (self.r_code in [200, 201]) and (self.r_text) :
            return json.loads(self.r_text)
        return None

    def category_list(self):
        self.handle_request("LIST", "api-categories")
        if (self.r_code == 200) and (self.r_text) :
            return json.loads(self.r_text)
        return None

    def category_get(self, category_id):
        # self.handle_request("GET", "api-categories", entry=category_id)
        self.handle_request("LIST", "api-categories")
        if (self.r_code == 200) and (self.r_text) :
            cat_list = json.loads(self.r_text)
            for elem in cat_list["list"] :
                if (elem["id"]   == category_id): return elem
                if (elem["name"] == category_id): return elem
        return None

    def category_get_id(self, category_id):
        # self.handle_request("GET", "api-categories", entry=category_id)
        self.handle_request("LIST", "api-categories")
        if (self.r_code == 200) and (self.r_text) :
            cat_list = json.loads(self.r_text)
            for elem in cat_list["list"] :
                if (elem["id"]   == category_id): return elem["id"]
                if (elem["name"] == category_id): return elem["id"]
        return None

    def category_delete(self, category_id):
        self.handle_request("DELETE", "api-categories", entry=category_id)
        if (self.r_code == 200) and (self.r_text) :
            return json.loads(self.r_text)
        return None

    # Interface functions
    def create(self, entity: Union[str, dict], backup: bool = True) -> Union[dict, None]:
        entity = super().create(entity=entity, backup=backup)
        if (self.isError()): return None
        if (isinstance(entity, str)):
            entity = ut.loadDataContent(entity)
        if ("name" in entity):
            name = entity["name"]
        else:
            self.error("name missing in category")
            return None
        if ("description" in entity):
            desc = entity["description"]
        else:
            self.error("description missing in category")
            return None
        return self.category_create(name, desc)

    def list(self, names: bool = False, ids: bool = False, count: bool = False) -> Union[list, None, int]:
        self.resetError()
        entity_list = self.category_list()
        if (self.isError()):  return None
        return self._list(entity_list, names=names, ids=ids, count=count)

    def get(self, idName: str = None, name: str = None, identifier: str = None) -> Union[dict, None]:
        entity_id = super().get(idName=idName, name=name, identifier=identifier)
        if (not entity_id): return None
        return self.category_get(entity_id)

    def update(self, entity: Union[str, dict], backup: bool = True) -> Union[dict, None]:
        entity = super().update(entity=entity, backup=backup)
        if (self.isError()): return None
        self.category_delete(entity[self.id_att])
        if (self.isError()): return None
        return self.create(entity, backup=False)

    def delete(self, idName: str = None, name: str = None, identifier: str = None, backup: bool = True) -> Union[dict, None]:
        entry = super().delete(idName=idName, name=name, identifier=identifier, backup=backup)
        if (self.isError()): return None
        self.category_delete(self.category_get_id(entry[self.id_att]))
        if (self.isError()): return None
        return entry


class Wso2PoliciesManager(DataStoreInterface, RestHandler):

    def __init__(self, server=None, entity_type="WS_Policies"):
        DataStoreInterface.__init__(self, entity_type=entity_type)
        RestHandler.__init__(self, server, service=StoreManager().store_get_service(entity_type))

    # policy_types = ["application", "custom", "advanced", "deny-policies", "subscription"]
    policy_types = ["application", "custom", "advanced", "deny-policies", "subscription", "mediation"]

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

    def policy_list(self, policyType : str = None) -> list:
        if ((not policyType) or (policyType not in Wso2PoliciesManager.policy_types)):
            policyList = list()
            for policy_type in Wso2PoliciesManager.policy_types:
                plist = self.policy_list(policy_type)
                if (plist):
                    policyList = policyList + plist
            return policyList
        self.handle_request("LIST", self.policy_type(policyType))
        if (self.r_code == 200) and (self.r_text) :
            pdata = json.loads(self.r_text)
            if ("list" not in pdata): return list()
            for pol in pdata["list"]:
                pol = Wso2PoliciesManager.policy_entry(pol, policyType)
            return pdata["list"]
        return None

    @staticmethod
    def policy_entry(pol : dict, policyType : str) -> dict:
        if ("policyId" in pol):        pol["id"] = pol["policyId"]
        if ("policyName" in pol):      pol["name"] = pol["policyName"]
        if ("description" not in pol): pol["description"] = pol["name"] if ("name" in pol) else ""
        pol["idType"] = pol["id"] + "/" + policyType
        pol["policyType"] = policyType
        return pol

    def policy_get(self, policy_id, policyType : str = "advanced"):
        if ("/" in policy_id):
            policyType = re.sub("^.*/", "", policy_id)
            policyId   = re.sub("/.*$", "", policy_id)
        else:
            policyId = policy_id
        self.handle_request("GET", self.policy_type(policyType), entry=policyId)
        if (self.r_code == 200) and (self.r_text) :
            pol = json.loads(self.r_text)
            pol = Wso2PoliciesManager.policy_entry(pol, policyType)
            return pol
        return None

    def policy_delete(self, policy_id, policyType : str = "advanced"):
        deleted_policy = self.policy_get(policy_id=policy_id, policyType=policyType)
        if ("/" in policy_id):
            policyType = re.sub("^.*/", "", policy_id)
            policyId   = re.sub("/.*$", "", policy_id)
        else:
            policyId = policy_id
        self.handle_request("DELETE", self.policy_type(policyType), entry=policyId)
        if (self.r_code == 200) and (self.r_text) :
            pol = json.loads(self.r_text)
            deleted_policy = Wso2PoliciesManager.policy_entry(deleted_policy, policyType)
            return deleted_policy
        return None

    # Interface functions
    def create(self, entity: Union[str, dict], backup: bool = True) -> Union[dict, None]:
        entity = super().create(entity=entity, backup=backup)
        if (self.isError()): return None
        if (isinstance(entity, str)):
            entity = ut.loadDataContent(entity)
        if ("type" in entity):
            policyType = entity["type"]
        else:
            self.error("Policy type missing in policy")
            return None
        if ("idType" in entity): del entity["idType"]
        return self.policy_create(ut.to_json(entity), "advanced")

    def list(self, names: bool = False, ids: bool = False, count: bool = False) -> Union[list, None, int]:
        self.resetError()
        entity_list = self.policy_list()
        if (self.isError()):  return None
        return self._list(entity_list, names=names, ids=ids, count=count)

    def get(self, idName: str = None, name: str = None, identifier: str = None) -> Union[dict, None]:
        entity_id = super().get(idName=idName, name=name, identifier=identifier)
        if (not entity_id): return None
        return self.policy_get(entity_id)

    def update(self, entity: Union[str, dict], backup: bool = True) -> Union[dict, None]:
        entity = super(DataStoreInterface, self).update(entity=entity, backup=backup)
        if (self.isError()): return None
        self.category_delete(entity[self.id_att])
        if (self.isError()): return None
        return self.create(entity, backup=False)

    def delete(self, idName: str = None, name: str = None, identifier: str = None, backup: bool = True) -> Union[dict, None]:
        entry = super().delete(idName=idName, name=name, identifier=identifier, backup=backup)
        if (self.isError()): return None
        self.policy_delete(entry[self.id_att])
        if (self.isError()): return None
        return entry


class Wso2ApisManager(DataStoreInterface, RestHandler):

    def __init__(self, server=None, entity_type="WS_Apis"):
        DataStoreInterface.__init__(self, entity_type=entity_type)
        RestHandler.__init__(self, server, service=StoreManager().store_get_service(entity_type))

    def api_list(self, details : bool = False):
        self.handle_request("LIST", "apis?limit=2000", service="publisher")
        if (self.r_code == 200) and (self.r_text) :
            pdata = json.loads(self.r_text)
            if ("list" not in pdata): return list()
            for api in pdata["list"]:
                api["nameVersion"] = api["name"] + "/" + api["version"]
                if (details): api["details"] = self.api_details(api["id"])
            return pdata["list"]
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
        if self.isError(): return None
        if (not swagger_file):
            if (self.r_code == 201) and (self.r_text) :
                return json.loads(self.r_text)
            return None
        r_val  = json.loads(self.r_text)
        api_id = r_val["id"]
        files = {'file': open(swagger_file, 'rb')}
        self.handle_request("PUT", "apis/"+api_id+"/swagger", files=files, service="publisher")
        if self.isError(): return None
        if (publish):
            self.api_publish(api_id)
            if self.isError(): return None
        return r_val

    def api_publish(self, api_id):
        api_id = self.api_id_by_name(api_id)
        self.handle_request("POST", "apis/change-lifecycle?apiId="+api_id+"&action=Publish", service="publisher")
        if (self.r_code == 200) and (self.r_text) :
            return json.loads(self.r_text)
        return None

    def api_lifecycle(self, api_id, state : str = "DEPRECATED"):
        # CREATED, PROTOTYPED, PUBLISHED, BLOCKED, DEPRECATED, RETIRED
        # "Publish" "Deploy as a Prototype" "Demote to Created" "Block" "Deprecate" "Re-Publish" "Retire"
        # https://apim.docs.wso2.com/en/4.0.0/learn/design-api/lifecycle-management/api-lifecycle/
        # https://apim.docs.wso2.com/en/3.2.0/learn/design-api/lifecycle-management/customize-api-life-cycle/
        if (state in ["PUBLISH"])    : state = "Publish"
        if (state in ["CREATED"])    : state = "Demote to Created"
        if (state in ["PROTOTYPED"]) : state = "Deploy as a Prototype"
        if (state in ["BLOCKED"])    : state = "Block"
        if (state in ["DEPRECATED"]) : state = "Deprecate"
        if (state in ["REPUBLISH"])  : state = "Re-Publish"
        if (state in ["RETIRED"])    : state = "Retire"
        api_id = self.api_id_by_name(api_id)
        state  = state.capitalize()
        self.handle_request("POST", "apis/change-lifecycle?apiId="+api_id+"&action="+state, service="publisher")
        if (self.r_code == 200) and (self.r_text) :
            return json.loads(self.r_text)
        return ut.to_json(ut.loadDataContent(self.r_text))

    def api_get(self, api_id, details : bool = False):
        api_id = self.api_id_by_name(api_id)
        self.handle_request("GET", "apis", entry=api_id, service="publisher")
        if (self.r_code == 200) and (self.r_text) :
            api = json.loads(self.r_text)
            api["nameVersion"] = api["name"] + "/" + api["version"]
            if (details): api["details"] = self.api_details(api_id)
            return api
        return None

    def api_get_swagger(self, api_id):
        api_id = self.api_id_by_name(api_id)
        self.handle_request("GET", "apis", entry=api_id+"/swagger", service="publisher")
        if (self.r_code == 200) and (self.r_text) :
            return json.loads(self.r_text)
        return None

    def api_get_thumbnail(self, api_id):
        api_id = self.api_id_by_name(api_id)
        self.handle_request("GET", "apis", entry=api_id+"/thumbnail", service="publisher")
        if (self.r_code == 200) and (self.r_text) :
            return json.loads(self.r_text)
        return None

    def api_get_policies(self, api_id):
        api_id = self.idByName(api_id)
        self.handle_request("GET", "apis", entry=api_id+"/subscription-policies", service="publisher")
        if (self.r_code == 200) and (self.r_text) :
            return json.loads(self.r_text)
        return None

    def api_delete(self, api_id : str = None, name : str = None, version: str = None):
        api_id = self.api_id_by_name(api_id)
        if (api_id) :
            self.handle_request("DELETE", "apis", entry=api_id, service="publisher")
            if (self.r_code == 200) and (self.r_text) :
                return json.loads(self.r_text)
            return None
        elif ((name) and (version)) :
            return self.api_delete(api_id=self.api_id_by_name(name, version))
        return None

    def api_details(self, api_id : str) -> Union[dict, str, None]:
        if (not api_id) : return "No API idName specified"
        if (api_id.upper() in ["", "ALL"]) : return "Invalid API idName : " + api_id
        api_id = self.api_id_by_name(api_id)
        api_details = dict()
        self.handle_request("GET", "apis", entry=api_id, service="publisher")
        api_details["api"] = self.r_data
        self.handle_request("GET", "apis", entry=api_id+"/swagger", service="publisher")
        api_details["swagger"] = self.r_data
        self.handle_request("GET", "apis", entry=api_id+"/thumbnail", service="publisher")
        api_details["thumbnail"] = self.r_data
        self.handle_request("GET", "apis", entry=api_id+"/subscription-policies", service="publisher")
        api_details["subscription-policies"] = self.r_data
        self.handle_request("GET", "apis", entry=api_id+"/resource-paths", service="publisher")
        api_details["resource-paths"] = self.r_data
        self.handle_request("GET", "apis", entry=api_id+"/asyncapi", service="publisher")
        api_details["asyncapi"] = self.r_data
        self.handle_request("GET", "apis", entry=api_id+"/lifecycle-history", service="publisher")
        api_details["lifecycle-history"] = self.r_data
        self.handle_request("GET", "apis", entry=api_id+"/lifecycle-state", service="publisher")
        api_details["lifecycle-state"] = self.r_data
        self.handle_request("GET", "apis", entry=api_id+"/revisions?query=deployed:true", service="publisher")

        self.handle_request("GET", "apis", entry=api_id+"/deployments", service="publisher")
        api_details["deployments"] = self.r_data
        self.handle_request("GET", "apis", entry=api_id+"/comments", service="publisher")
        api_details["comments"] = self.r_data
        self.handle_request("GET", "apis", entry=api_id+"/monetize", service="publisher")
        api_details["monetize"] = self.r_data
        self.handle_request("GET", "apis", entry=api_id+"/documents", service="publisher")
        api_details["documents"] = self.r_data
        self.handle_request("GET", "apis", entry=api_id+"/mediation-policies", service="publisher")
        api_details["mediation-policies"] = self.r_data
        self.handle_request("GET", "apis", entry=api_id+"/auditapi", service="publisher")
        api_details["auditapi"] = self.r_data
        self.handle_request("GET", "apis", entry=api_id+"/external-stores", service="publisher")
        api_details["external-stores"] = self.r_data
        self.handle_request("GET", "apis", entry=api_id+"/client-certificates", service="publisher")  # ?alias=wso2carbon
        api_details["client-certificates"] = self.r_data
        self.handle_request("GET", "subscriptions?"+api_id, service="publisher")
        api_details["external-stores"] = self.r_data
        return api_details

    # Interface functions
    def create(self, entity: Union[str, dict], backup: bool = True) -> Union[dict, None]:
        entity = super(DataStoreInterface, self).create(entity=entity, backup=backup)
        if (self.isError()): return None
        if (isinstance(entity, str)): entity = ut.loadDataContent(entity)
        return self.api_create(ut.to_json(entity))

    def list(self, names: bool = False, ids: bool = False, count: bool = False) -> Union[list, None, int]:
        self.resetError()
        entity_list = self.api_list()
        if (self.isError()):  return None
        return self._list(entity_list, names=names, ids=ids, count=count)

    def get(self, idName: str = None, name: str = None, identifier: str = None) -> Union[dict, None]:
        entity_id = super().get(idName=idName, name=name, identifier=identifier)
        if (not entity_id): return None
        return self.api_get(entity_id)

    def update(self, entity: Union[str, dict], backup: bool = True) -> Union[dict, None]:
        entity = super(DataStoreInterface, self).update(entity=entity, backup=backup)
        if (self.isError()): return None
        self.api_delete(entity[self.id_att])
        if (self.isError()): return None
        return self.create(entity, backup=False)

    def delete(self, idName: str = None, name: str = None, identifier: str = None, backup: bool = True) -> Union[dict, None]:
        entry = super().delete(idName=idName, name=name, identifier=identifier, backup=backup)
        if (self.isError()): return None
        self.api_delete(entry[self.id_att])
        if (self.isError()): return None
        return entry


class Wso2ProductsManager(DataStoreInterface, RestHandler):
    def __init__(self, server=None, entity_type="WS_Product"):
        DataStoreInterface.__init__(self, entity_type=entity_type)
        RestHandler.__init__(self, server, service=StoreManager().store_get_service(entity_type))

    def product_create(self, product : str):
        self.handle_request("POST", "api-products", payload=product, service="publisher")
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

    # Interface functions
    def create(self, entity: Union[str, dict], backup: bool = True) -> Union[dict, None]:
        entity = super(DataStoreInterface, self).create(entity=entity, backup=backup)
        if (self.isError()): return None
        if (isinstance(entity, str)): entity = ut.loadDataContent(entity)
        return self.product_create(ut.to_json(entity))

    def list(self, names: bool = False, ids: bool = False, count: bool = False) -> Union[list, None, int]:
        self.resetError()
        entity_list = self.product_list()
        if (self.isError()):  return None
        return self._list(entity_list, names=names, ids=ids, count=count)

    def get(self, idName: str = None, name: str = None, identifier: str = None) -> Union[dict, None]:
        entity_id = super().get(idName=idName, name=name, identifier=identifier)
        if (not entity_id): return None
        return self.product_get(entity_id)

    def update(self, entity: Union[str, dict], backup: bool = True) -> Union[dict, None]:
        entity = super(DataStoreInterface, self).update(entity=entity, backup=backup)
        if (self.isError()): return None
        self.product_delete(entity[self.id_att])
        if (self.isError()): return None
        return self.create(entity, backup=False)

    def delete(self, idName: str = None, name: str = None, identifier: str = None, backup: bool = True) -> Union[dict, None]:
        entry = super().delete(idName=idName, name=name, identifier=identifier, backup=backup)
        if (self.isError()): return None
        self.product_delete(entry[self.id_att])
        if (self.isError()): return None
        return entry


class Wso2SubscriptionsManager(RestHandler):

    def __init__(self, ws_server=None):
        if (not ws_server) : ws_server = AEPCTL_Configuration.get("WSO2_SERVER")
        super().__init__(ws_server)

    def settings_get(self):
        settings = ut.SuperDict()
        settings["id"]   = "PUBLISHER_PORTAL"
        settings["name"] = "apim"
        settings["description"] = "Publisher Portal Settings"
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
            return self.subscription_delete(app_id=self.subscription_id_by_name(name))
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


class Wso2ApplicationsManager(DataStoreInterface, RestHandler):

    def __init__(self, server=None, entity_type="WS_Applications"):
        DataStoreInterface.__init__(self, entity_type=entity_type)
        RestHandler.__init__(self, server, service=StoreManager().store_get_service(entity_type))

    def application_create(self, application : str):
        self.handle_request("POST", "applications", payload=application, service="devportal")
        if (self.r_code == 201) and (self.r_text) :
            return json.loads(self.r_text)
        self.error(json.loads(self.r_text))
        return None

    def application_list(self, names : bool = True):
        self.handle_request("LIST", "applications?limit=2000", service="devportal")
        if (self.r_code == 200) and (self.r_text) :
            return json.loads(self.r_text)
        self.error(json.loads(self.r_text))
        return None

    def application_get(self, app_id):
        self.handle_request("GET", "applications", entry=app_id, service="devportal")
        if (self.r_code == 200) and (self.r_text) :
            return json.loads(self.r_text)
        self.error(json.loads(self.r_text))
        return None

    def application_delete(self, app_id: str = None, name: str = None):
        if (app_id) :
            self.handle_request("DELETE", "applications", entry=app_id, service="devportal")
            if (self.r_code == 200) and (self.r_text) :
                return json.loads(self.r_text)
            self.error(json.loads(self.r_text))
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
        self.error(json.loads(self.r_text))
        return None

    def application_get_keys(self, appname_id : str = None):
        app_id = self.application_id_by_name(appname_id)
        if (not app_id): app_id = appname_id
        if (not app_id) : return None
        self.handle_request("GET", "applications/"+app_id+"/oauth-keys", service="devportal")
        return self.getData()

    def application_generate_keys(self, appname_id : str = None):
        app_id = self.application_id_by_name(appname_id)
        if (not app_id): app_id = appname_id
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

    # Interface functions
    def create(self, entity: Union[str, dict], backup: bool = True) -> Union[dict, None]:
        entity = super(DataStoreInterface, self).create(entity=entity, backup=backup)
        if (self.isError()): return None
        if (isinstance(entity, str)): entity = ut.loadDataContent(entity)
        return self.application_create(ut.to_json(entity))

    def list(self, names: bool = False, ids: bool = False, count: bool = False) -> Union[list, None, int]:
        self.resetError()
        entity_list = self.application_list()
        if (self.isError()):  return None
        return self._list(entity_list, names=names, ids=ids, count=count)

    def get(self, idName: str = None, name: str = None, identifier: str = None) -> Union[dict, None]:
        entity_id = super().get(idName=idName, name=name, identifier=identifier)
        if (not entity_id): return None
        return self.application_get(entity_id)

    def update(self, entity: Union[str, dict], backup: bool = True) -> Union[dict, None]:
        entity = super().update(entity=entity, backup=backup)
        if (self.isError()): return None
        self.category_delete(entity[self.id_att])
        if (self.isError()): return None
        return self.create(entity, backup=False)

    def delete(self, idName: str = None, name: str = None, identifier: str = None, backup: bool = True) -> Union[dict, None]:
        entry = super().delete(idName=idName, name=name, identifier=identifier, backup=backup)
        if (self.isError()): return None
        self.application_delete(entry[self.id_att])
        if (self.isError()): return None
        return entry


class Wso2Provisioning():

    def __init__(self, service : str = "file"):
        self.service           = service

    def error(self, text):
        logger.error("Api not found : "+text)
        return text

    def provisionCategory(self, categoryName : str, dataStore: str ="file") -> bool:
        if (categoryName.upper() == "ALL"):
            cat_store = StoreManager().getStore(name="Categories", store_type=dataStore)
            catList   = cat_store.list(names=True)
            rc = True
            for categoryName in catList:
                rc = rc and self.provisionCategory(categoryName)
            return rc
        logger.info("Provisioning Category : "+categoryName)
        cat_store = StoreManager().getStore(name="Categories", store_type=dataStore)
        category  = cat_store.get(categoryName)
        if (not category): return self.error("Category not found : "+categoryName)
        # Get Category Details
        cat_name = category[cat_store.name_att]
        # Create Context / Maybe load other policies
        rendering_context = category
        # Render Category Descriptor for WS02
        cat_dir     = CONFIG_DIRECTORY+os.sep+"templates"+os.sep+"categories"
        desc_template = cat_dir+os.sep+"category_create.json"
        cat_desc_file = cat_dir+os.sep+cat_name+"_desc.json"
        ut.Template.renderFile(desc_template, cat_desc_file, rendering_context)
        cat_desc_json = ut.loadDataFile(cat_desc_file)
        logger.info("WSO2 Category Descriptor : "+ut.to_json(cat_desc_json))
        # Create Category in WSO2
        catMgr = StoreManager().getStore(name="ws_categories", store_type="ws")
        rc = catMgr.create(cat_desc_json)
        if (rc == None) : return catMgr.getError()
        return rc

    def provisionPolicy(self, policyName : str, dataStore: str ="file") -> bool:
        if (policyName.upper() == "ALL"):
            pol_store = StoreManager().getStore(name="UsagePolicies", store_type=dataStore)
            polList   = pol_store.list(names=True)
            rc = True
            for policyName in polList:
                rc = rc and self.provisionPolicy(policyName)
            return rc
        logger.info("Provisioning Policy : "+policyName)
        pol_store = StoreManager().getStore(name="UsagePolicies", store_type=dataStore)
        policy  = pol_store.get(policyName)
        if (not policy): return self.error("Policy not found : "+policyName)
        # Get Policy Details
        pol_name = policy[pol_store.name_att]
        # Create Context / Maybe load other policies
        rendering_context = policy
        # Render Policy Descriptor for WS02
        pol_dir     = CONFIG_DIRECTORY+os.sep+"templates"+os.sep+"policies"
        desc_template = pol_dir+os.sep+"policy_create.json"
        pol_desc_file = pol_dir+os.sep+pol_name+"_desc.json"
        ut.Template.renderFile(desc_template, pol_desc_file, rendering_context)
        pol_desc_json = ut.loadDataFile(pol_desc_file)
        logger.info("WSO2 Policy Descriptor : "+ut.to_json(pol_desc_json))
        # Create Policy in WSO2
        ws_polMgr = StoreManager().getStore(name="ws_policies", store_type="ws")
        rc = ws_polMgr.create(pol_desc_json)
        if (rc == None) : return ws_polMgr.getError()
        policy['ws_key']    = rc['policyId']
        rc = pol_store.save(entity=policy)
        if (rc == None) : return policy.getError()
        return rc

    def provisionAPI(self, apiName : str, model : str = "nef_template", publish : bool = True, dataStore: str ="file") -> bool:
        if (apiName.upper() == "ALL"):
            api_store = StoreManager().getStore(name="APIs", store_type=dataStore)
            apiList   = api_store.list(names=True)
            rc = True
            for apiName in apiList:
                rc = rc and self.provisionAPI(apiName)
            return rc
        logger.info("Provisioning API : " + apiName)
        api_store = StoreManager().getStore(name="APIs", store_type=self.service)
        api       = api_store.get(apiName)
        if (not api): return self.error("Api not found : " + apiName)
        # Get API Details
        api_name    = api["API_Name"]
        api_ver     = api["Version"]
        # Checks
        api_dir     = CONFIG_DIRECTORY+os.sep+"templates"+os.sep+"apis"+os.sep+model
        api_path    = DATA_DIRECTORY+os.sep+"apis"+os.sep+api_name+"-"+api_ver
        swg_path    = api_path+os.sep+"swagger"+os.sep+"dir"
        add_swagger = api_dir+os.sep+"swagger"
        if (not ut.safeDirExist(api_dir)):
            return self.error("Directory not found : "+api_dir)
        if (ut.safeDirExist(api_path)):
            shutil.rmtree(api_path)
        if (ut.safeDirExist(add_swagger)):
            shutil.copytree(add_swagger, swg_path)
        else:
            os.makedirs(swg_path)
        if (not ut.safeDirExist(api_path)):
            return self.error("Directory not found : "+api_path)
        # Check the Swagger Definition
        b64yaml = re.sub("@b64file:.*:", "", api["YAML"])
        swagger_str  = ut.to_b64_to_str(b64yaml)
        swagger_json = ut.loadDataContent(swagger_str)
        if (not swagger_json): return self.error("Cannot Decode Swagger YAML in API Definition : "+apiName)
        ut.saveDataFile(swagger_json, swg_path+os.sep+"swagger.yaml")
        # Create Context / Maybe load other policies
        rendering_context = api
        rendering_context["SWAGGER"] = swagger_json
        rendering_context["API_Context"] = "/wso2am/" + api["API_Name"].replace("3gpp-", "")
        rendering_context["API_Version"] = api["Version"]
        # Render API Descriptor for WS02
        desc_template = api_dir+os.sep+"api-create-template.json"
        api_desc_file = api_path+os.sep+api_name+"_desc.json"
        ut.Template.renderFile(desc_template, api_desc_file, rendering_context)
        api_desc_json = ut.loadDataFile(api_desc_file)
        logger.info("WSO2 API Descriptor : "+ut.to_json(api_desc_json))
        # Zip Swagger Files
        api_swagger = api_path+os.sep+api_name
        shutil.make_archive(api_swagger, 'zip', ut.get_directory(swg_path))
        # Create API in WSO2
        apim = StoreManager().getStore(name="apis", store_type="ws")
        rc = apim.api_create(api_desc_json, api_swagger+".zip", publish=publish)
        if (rc == None) : return apim.Error()
        api['ws_key']    = rc['id']
        rc = api_store.save(entity=api)
        if (rc == None) : return api_store.getError()
        return rc

    def publishAPI(self, apiName: str) -> bool:
        pass

    def unpublishAPI(self, apiName: str) -> bool:
        pass

    def provisionContact(self, userName, dataStore: str ="file") -> bool:
        if (userName.upper() == "ALL"):
            ctc_store = StoreManager().getStore(name="Contacts", store_type=dataStore)
            ctcList   = ctc_store.list(names=True)
            rc = True
            for ctcName in ctcList:
                rc = rc and self.provisionContact(ctcName)
            return rc
        logger.info("Provisioning Contact : " + userName)
        ctc_store = StoreManager().getStore(name="Contacts", store_type=dataStore)
        contact   = ctc_store.get(userName)
        if (not contact): return self.error("Contact not found : "+userName)
        # Get Contact Details
        user = dict()
        user["name"] = contact[ctc_store.name_att]
        user["role"] = contact["Role"] if "Role" in contact else contact["role"]
        # Create User in WSO2
        usrMgr = StoreManager().getStore(name="ws_users", store_type="ws")
        rc = usrMgr.save(entity=user)
        if (rc == None) : return usrMgr.getError()
        return rc

    def provisionService(self, serviceName: str, dataStore: str ="file") -> bool:
        if (serviceName.upper() == "ALL"):
            svc_store = StoreManager().getStore(name="Services", store_type=dataStore)
            svcList   = svc_store.list(names=True)
            rc = True
            for svcName in svcList:
                rc = rc and self.provisionService(svcName)
            return rc
        logger.info("Provisioning Service : " + serviceName)
        svc_store = StoreManager().getStore(name="Services", store_type=dataStore)
        service  = svc_store.get(serviceName)
        if (not service): return self.error("Service not found : "+serviceName)
        # Get Service Details
        app_name = service[svc_store.name_att]
        # Create Context / Maybe load other policies
        rendering_context = service
        # Render Category Descriptor for WS02
        app_dir       = CONFIG_DIRECTORY+os.sep+"templates"+os.sep+"applications"
        desc_template = app_dir+os.sep+"application_create.json"
        app_desc_file = app_dir+os.sep+app_name+"_desc.json"
        ut.Template.renderFile(desc_template, app_desc_file, rendering_context)
        app_desc_json = ut.loadDataFile(app_desc_file)
        logger.info("WSO2 Application Descriptor : "+ut.to_json(app_desc_json))
        # Create Application in WSO2
        appMgr = StoreManager().getStore(name="ws_applications", store_type="ws")
        rc = appMgr.application_create(app_desc_json)
        if (rc == None) : return appMgr.getError()
        service['ws_id']    = rc['applicationId']
        keys = appMgr.application_generate_keys(rc[appMgr.id_att])
        if (rc == None) : return appMgr.getError()
        service['consumerKey']    = keys['consumerKey']
        service['consumerSecret'] = keys['consumerSecret']
        # keys = appMgr.application_get_keys(rc[appMgr.id_att])
        rc = svc_store.save(entity=service)
        if (rc == None) : return svc_store.getError()
        return rc

    def subscribeServiceToApi(self, subscriptionID : str, dataStore: str ="file") -> bool:
        subscription_store = StoreManager().getStore(name="Subscriptions", store_type=dataStore)
        subscription = subscription_store.get(subscriptionID)
        if (not subscription): return self.error("subscription not found : " + subscriptionID)
        serviceID   = subscription["AppID"]
        apiID       = subscription["ApiID"]
        policyID    = "TestPolicy1"  # subscription["TestPolicy1"]
        logger.info("Subscription [" + subscriptionID + "]")
        logger.info("Subscribe Service [" + serviceID + "] to Api [" + apiID + "]")
        logger.info("Policy [" + policyID + "]")
        service_store = StoreManager().getStore(name="Services", store_type=dataStore)
        service = service_store.get(serviceID)
        if (not service): return self.error("Service not found : " + serviceID)
        ws_appID = service["ws_id"]
        api_store = StoreManager().getStore(name="Apis", store_type=dataStore)
        api = api_store.get(apiID)
        if (not api): return self.error("Api not found : " + apiID)
        ws_apiID = api["ws_key"]
        # Get Subscription Details
        subs_name = subscriptionID
        # Create Context / Maybe load other policies
        rendering_context = subscription
        rendering_context["ws_apiID"] = ws_apiID
        rendering_context["ws_appID"] = ws_appID
        rendering_context["api"]      = api
        rendering_context["service"]  = service
        rendering_context["policy"]   = policyID
        # Render Category Descriptor for WS02
        app_dir        = CONFIG_DIRECTORY+os.sep+"templates"+os.sep+"subscribe"
        desc_template  = app_dir+os.sep+"subscribe.json"
        subs_desc_file = app_dir+os.sep+subs_name+"_desc.json"
        ut.Template.renderFile(desc_template, subs_desc_file, rendering_context)
        app_desc_json = ut.loadDataFile(subs_desc_file)
        logger.info("WSO2 Subscription Descriptor : "+ut.to_json(subs_desc_file))
        # Create Subscription in WSO2
        devMgr = Wso2SubscriptionsManager()
        rc = devMgr.subscribe(app_id=ws_appID, api_id=ws_apiID, policy=policyID)
        if (rc == None) : return devMgr.getError()
        subscription["ws_id"] = rc["subscriptionId"]
        subscription_store.save(subscription)
        if (rc == None) : return subscription_store.getError()
        return rc

    def extractWso2Apis(self, idName : str = "all", dataStore : str = None) -> list:
        wsMgr   = Wso2ApisManager()
        apiList = wsMgr.api_list()
        dirname  = "data"+os.sep+"nef-apis-dump"
        ut.safeCreateDir(dirname)
        api_list = list()
        for api in apiList["list"] :
            if (idName.lower() != "all"):
                if (idName != api["id"]): continue
                if (idName != api["name"]+"-"+api["version"]): continue
                if (idName != api["name"]+"/"+api["version"]): continue
                if (idName != api["name"]): continue
            apiId = api["id"]
            apiname = api["name"]+"-"+api["version"]
            logger.info("extractWso2Apis : "+str(apiname)+" : "+apiId)
            api_dir = dirname+os.sep+apiname
            ut.safeCreateDir(api_dir)
            res = wsMgr.api_get(apiId)
            ut.saveDataFile(res, api_dir+os.sep+"api_desc.json")
            res = wsMgr.api_get_swagger(apiId)
            ut.saveDataFile(res, api_dir+os.sep+"swagger.json")
            res = wsMgr.api_get_thumbnail(apiId)
            ut.saveDataFile(res, api_dir+os.sep+"thumbnail.json")
            res = wsMgr.api_get_policies(apiId)
            ut.saveDataFile(res, api_dir+os.sep+"policies.json")

            api_desc      = ut.loadDataFile(api_dir+os.sep+"api_desc.json")
            api_swagger   = ut.loadDataFile(api_dir+os.sep+"swagger.json")
            api_policies  = ut.loadDataFile(api_dir+os.sep+"policies.json")
            api_thumbnail = ut.loadDataFile(api_dir+os.sep+"thumbnail.json")
            if ("x-wso2-production-endpoints" in api_swagger): del api_swagger["x-wso2-production-endpoints"]
            if ("x-wso2-response-cache"       in api_swagger): del api_swagger["x-wso2-response-cache"]
            if ("x-wso2-sandbox-endpoints"    in api_swagger): del api_swagger["x-wso2-sandbox-endpoints"]
            if ("x-wso2-transports"           in api_swagger): del api_swagger["x-wso2-transports"]
            if ("x-wso2-cors"                 in api_swagger): del api_swagger["x-wso2-cors"]
            if ("x-wso2-basePath"             in api_swagger): del api_swagger["x-wso2-basePath"]
            if ("x-wso2-auth-header"          in api_swagger): del api_swagger["x-wso2-auth-header"]

            swagger_title   = api_swagger["info"]["title"]
            swagger_descr   = api_swagger["info"]["description"].replace("©", "(c)").replace("\u00a9", "(c)").replace("\n", " ")
            swagger_version = api_swagger["info"]["version"]
            swagger_doc     = api_swagger["externalDocs"]["description"]
            swagger_doc_url = api_swagger["externalDocs"]["url"]
            api_desc["description"] = api_desc["description"].replace("©", "(c)").replace("\u00a9", "(c)").replace("\n", " ")
            ds_api = dict()
            ds_api["API_Name"]           = api_desc["name"]        if ("name"        in api_desc and api_desc["name"])        else swagger_title
            ds_api["API_Description"]    = api_desc["description"] if ("description" in api_desc and api_desc["description"]) else swagger_descr
            ds_api["Version"]            = api_desc["version"]     if ("version"     in api_desc and api_desc["version"])     else swagger_version
            ds_api["API_Provider_Name"]  = api_desc["provider"]
            ds_api["API_Category"]       = api_desc["categories"]  if (len(api_desc["categories"]) != 0) else [ "NEF" ]
            ds_api["Charging_Policies"]  = api_desc["policies"][0]
            ds_api["API_Documentation"]  = api_desc["description"] if ("description" in api_desc and api_desc["description"]) else swagger_doc
            ds_api["API_Use_Cases"]      = api_desc["description"] if ("description" in api_desc and api_desc["description"]) else swagger_doc_url
            ds_api["YAML"]               = "b64file:"+ut.get_basename(api_dir+os.sep+"swagger.json")
            # Save Locally
            desc_api = dict()
            desc_api["entity"] = "apis"
            desc_api["entry"]  = ds_api
            ut.saveDataFile(desc_api, api_dir+os.sep+apiname+"_api.json")
            # Store in DataStore
            if (dataStore) :
                store = StoreManager().getStore(name="apis", file=(dataStore.lower() == "file"))
                store.create(ds_api)
            api_list.append(ds_api)
        return api_list

    def apiFileForFactoryData(self, api_file_name, api_category : str="Default" , loadInStore : bool=False, dataStore="file") -> dict:
        store = StoreManager().getStore(name="apis", file=(dataStore.lower() == "file"))

        logger.info("apiFileForDataStore : Processing : " + str(api_file_name))
        api_name = ut.get_nakedname(api_file_name)
        api_name = re.sub("-[0-9].*$", "", api_name)
        swagger_api = ut.loadDataFile(api_file_name)
        if ("swagger" in api_name) :
            api_name = swagger_api["info"]["title"]
            api_name = re.sub(" ", "_", api_name)
        api_desc = dict()
        api_desc["API_Name"] = api_name
        api_desc["API_Provider_Name"] = "admin"
        api_desc["API_Description"] = swagger_api["info"]["title"].replace("©", "(c)").replace("\u00a9", "(c)").replace("\n", " ")
        api_desc["Version"]         = swagger_api["info"]["version"]
        api_desc["Charging_Policies"] = "Gold"
        api_desc["API_Documentation"] = "No Documentation"
        api_desc["API_Category"]      = [ api_category ]
        api_desc["API_Use_Cases"]     = "No Use Cases"
        api_desc["YAML"]              = "@b64file:"+ut.get_basename(api_file_name)

        # Save Locally
        api_dir_name = ut.get_directory(api_file_name)
        desc_api = dict()
        desc_api["entity"] = "apis"
        desc_api["entry"] = api_desc
        api_desc_filename = api_dir_name + os.sep + api_name + "_api.json"
        logger.info("apiFileForFactoryData : Desc API : "+api_desc_filename)
        ut.saveDataFile(desc_api, api_desc_filename)

        if (not loadInStore):
            return desc_api

        # Store in DataStore Locally
        if (store.exist(api_name)):
            # id = store.id_by_name(api_name)
            store.update(api_desc, backup=False)
        else:
            store.create(api_desc, backup=False)
        return api_desc

    def apiDirForFactoryData(self, api_dir_pattern, api_category : str = "Default" , loadInStore : bool = False,  dataStore="file") -> list:
        api_list = list()
        exclude = ut.get_directory(api_dir_pattern) + os.sep + "*_api.json"
        files = set(glob.glob(api_dir_pattern)) - set(glob.glob(exclude))
        for file in files :
            api_list.append(self.apiFileForFactoryData(file, api_category, loadInStore, dataStore))
        return api_list

    def prepareApisForFactoryData(self, loadInStore : bool=False, dataStore="file") -> list:
        api_list = list()
        store = StoreManager().getStore(name="apis", file=(dataStore.lower() == "file"))
        StoreManager().store_back_up(store_type=dataStore)

        # NEF APIs Desc should be ready from WS02 Extraction
        # Only load in DataStore id required
        dir_name =  "data"+os.sep+"nef-apis-dump"
        files = glob.glob(dir_name+os.sep+'*'+os.sep+'*_api.json')
        logger.info(str(dir_name+os.sep+'*'+os.sep+'*_api.json'))
        logger.info(str(files))
        for file in files :
            logger.info("prepareApisForFactoryData : "+str(file))
            # Store in DataStore Locally
            ds_api      = ut.loadDataFile(file)
            api_name    = ds_api["entry"]["API_Name"]
            if (loadInStore):
                if (store.exist(api_name)):
                    store.update(ds_api, backup=False)
                else:
                    store.create(ds_api, backup=False)
            api_list.append(ds_api)

        dir_name   = "data"+os.sep+"camara-apis-dump"+os.sep+'*'+os.sep+'*.yaml'
        api_list = api_list + self.apiDirForFactoryData(api_dir_pattern=dir_name, api_category="Camara", loadInStore=loadInStore, dataStore=dataStore)

        dir_name   = "data"+os.sep+"public-apis-dump"+os.sep+'*'+os.sep+'*.json'
        api_list = api_list + self.apiDirForFactoryData(api_dir_pattern=dir_name, api_category="Public", loadInStore=loadInStore, dataStore=dataStore)

        dir_name   = "data"+os.sep+"public-apis-dump"+os.sep+'*'+os.sep+'*.yaml'
        api_list = api_list + self.apiDirForFactoryData(api_dir_pattern=dir_name, api_category="Public", loadInStore=loadInStore, dataStore=dataStore)

        dir_name   = "data"+os.sep+"tmf-apis-dump"+os.sep+'*'+os.sep+'*'+os.sep+'*.json'
        api_list = api_list + self.apiDirForFactoryData(api_dir_pattern=dir_name, api_category="TMF", loadInStore=loadInStore, dataStore=dataStore)

        return api_list


###
### TMF DataStore
###


class TmfApisManager(DataStoreInterface, RestHandler):

    def __init__(self, server=None, entity_type="WS_Apis"):
        DataStoreInterface.__init__(self, entity_type=entity_type)
        RestHandler.__init__(self, server, service=StoreManager().store_get_service(entity_type))

    def api_list(self, details : bool = False):
        self.handle_request("LIST", "apis?limit=2000", service="publisher")
        if (self.r_code == 200) and (self.r_text) :
            pdata = json.loads(self.r_text)
            if ("list" not in pdata): return list()
            for api in pdata["list"]:
                api["nameVersion"] = api["name"] + "/" + api["version"]
                if (details): api["details"] = self.api_details(api["id"])
            return pdata["list"]
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
        if self.isError(): return None
        if (not swagger_file):
            if (self.r_code == 201) and (self.r_text) :
                return json.loads(self.r_text)
            return None
        r_val  = json.loads(self.r_text)
        api_id = r_val["id"]
        files = {'file': open(swagger_file, 'rb')}
        self.handle_request("PUT", "apis/"+api_id+"/swagger", files=files, service="publisher")
        if self.isError(): return None
        if (publish):
            self.api_publish(api_id)
            if self.isError(): return None
        return r_val

    def api_publish(self, api_id):
        api_id = self.api_id_by_name(api_id)
        self.handle_request("POST", "apis/change-lifecycle?apiId="+api_id+"&action=Publish", service="publisher")
        if (self.r_code == 200) and (self.r_text) :
            return json.loads(self.r_text)
        return None

    def api_lifecycle(self, api_id, state : str = "DEPRECATED"):
        # CREATED, PROTOTYPED, PUBLISHED, BLOCKED, DEPRECATED, RETIRED
        # "Publish" "Deploy as a Prototype" "Demote to Created" "Block" "Deprecate" "Re-Publish" "Retire"
        # https://apim.docs.wso2.com/en/4.0.0/learn/design-api/lifecycle-management/api-lifecycle/
        # https://apim.docs.wso2.com/en/3.2.0/learn/design-api/lifecycle-management/customize-api-life-cycle/
        if (state in ["PUBLISH"])    : state = "Publish"
        if (state in ["CREATED"])    : state = "Demote to Created"
        if (state in ["PROTOTYPED"]) : state = "Deploy as a Prototype"
        if (state in ["BLOCKED"])    : state = "Block"
        if (state in ["DEPRECATED"]) : state = "Deprecate"
        if (state in ["REPUBLISH"])  : state = "Re-Publish"
        if (state in ["RETIRED"])    : state = "Retire"
        api_id = self.api_id_by_name(api_id)
        state  = state.capitalize()
        self.handle_request("POST", "apis/change-lifecycle?apiId="+api_id+"&action="+state, service="publisher")
        if (self.r_code == 200) and (self.r_text) :
            return json.loads(self.r_text)
        return ut.to_json(ut.loadDataContent(self.r_text))

    def api_get(self, api_id, details : bool = False):
        api_id = self.api_id_by_name(api_id)
        self.handle_request("GET", "apis", entry=api_id, service="publisher")
        if (self.r_code == 200) and (self.r_text) :
            api = json.loads(self.r_text)
            api["nameVersion"] = api["name"] + "/" + api["version"]
            if (details): api["details"] = self.api_details(api_id)
            return api
        return None

    def api_get_swagger(self, api_id):
        api_id = self.api_id_by_name(api_id)
        self.handle_request("GET", "apis", entry=api_id+"/swagger", service="publisher")
        if (self.r_code == 200) and (self.r_text) :
            return json.loads(self.r_text)
        return None

    def api_get_thumbnail(self, api_id):
        api_id = self.api_id_by_name(api_id)
        self.handle_request("GET", "apis", entry=api_id+"/thumbnail", service="publisher")
        if (self.r_code == 200) and (self.r_text) :
            return json.loads(self.r_text)
        return None

    def api_get_policies(self, api_id):
        api_id = self.idByName(api_id)
        self.handle_request("GET", "apis", entry=api_id+"/subscription-policies", service="publisher")
        if (self.r_code == 200) and (self.r_text) :
            return json.loads(self.r_text)
        return None

    def api_delete(self, api_id : str = None, name : str = None, version: str = None):
        api_id = self.api_id_by_name(api_id)
        if (api_id) :
            self.handle_request("DELETE", "apis", entry=api_id, service="publisher")
            if (self.r_code == 200) and (self.r_text) :
                return json.loads(self.r_text)
            return None
        elif ((name) and (version)) :
            return self.api_delete(api_id=self.api_id_by_name(name, version))
        return None

    def api_details(self, api_id : str) -> dict:
        if (not api_id) : return "No API idName specified"
        if (api_id.upper() in ["", "ALL"]) : return "Invalid API idName : " + api_id
        api_id = self.api_id_by_name(api_id)
        api_details = dict()
        self.handle_request("GET", "apis", entry=api_id, service="publisher")
        api_details["api"] = self.r_data
        self.handle_request("GET", "apis", entry=api_id+"/swagger", service="publisher")
        api_details["swagger"] = self.r_data
        self.handle_request("GET", "apis", entry=api_id+"/thumbnail", service="publisher")
        api_details["thumbnail"] = self.r_data
        self.handle_request("GET", "apis", entry=api_id+"/subscription-policies", service="publisher")
        api_details["subscription-policies"] = self.r_data
        self.handle_request("GET", "apis", entry=api_id+"/resource-paths", service="publisher")
        api_details["resource-paths"] = self.r_data
        self.handle_request("GET", "apis", entry=api_id+"/asyncapi", service="publisher")
        api_details["asyncapi"] = self.r_data
        self.handle_request("GET", "apis", entry=api_id+"/lifecycle-history", service="publisher")
        api_details["lifecycle-history"] = self.r_data
        self.handle_request("GET", "apis", entry=api_id+"/lifecycle-state", service="publisher")
        api_details["lifecycle-state"] = self.r_data
        self.handle_request("GET", "apis", entry=api_id+"/revisions?query=deployed:true", service="publisher")

        self.handle_request("GET", "apis", entry=api_id+"/deployments", service="publisher")
        api_details["deployments"] = self.r_data
        self.handle_request("GET", "apis", entry=api_id+"/comments", service="publisher")
        api_details["comments"] = self.r_data
        self.handle_request("GET", "apis", entry=api_id+"/monetize", service="publisher")
        api_details["monetize"] = self.r_data
        self.handle_request("GET", "apis", entry=api_id+"/documents", service="publisher")
        api_details["documents"] = self.r_data
        self.handle_request("GET", "apis", entry=api_id+"/mediation-policies", service="publisher")
        api_details["mediation-policies"] = self.r_data
        self.handle_request("GET", "apis", entry=api_id+"/auditapi", service="publisher")
        api_details["auditapi"] = self.r_data
        self.handle_request("GET", "apis", entry=api_id+"/external-stores", service="publisher")
        api_details["external-stores"] = self.r_data
        self.handle_request("GET", "apis", entry=api_id+"/client-certificates", service="publisher")  # ?alias=wso2carbon
        api_details["client-certificates"] = self.r_data
        self.handle_request("GET", "subscriptions?"+api_id, service="publisher")
        api_details["external-stores"] = self.r_data
        return api_details

    # Interface functions
    def create(self, entity: Union[str, dict], backup: bool = True) -> Union[dict, None]:
        entity = super(DataStoreInterface, self).create(entity=entity, backup=backup)
        if (self.isError()): return None
        if (isinstance(entity, str)): entity = ut.loadDataContent(entity)
        return self.api_create(ut.to_json(entity))

    def list(self, names: bool = False, ids: bool = False, count: bool = False) -> Union[list, None, int]:
        self.resetError()
        entity_list = self.api_list()
        if (self.isError()):  return None
        return self._list(entity_list, names=names, ids=ids, count=count)

    def get(self, idName: str = None, name: str = None, identifier: str = None) -> Union[dict, None]:
        entity_id = super().get(idName=idName, name=name, identifier=identifier)
        if (not entity_id): return None
        return self.api_get(entity_id)

    def update(self, entity: Union[str, dict], backup: bool = True) -> Union[dict, None]:
        entity = super(DataStoreInterface, self).update(entity=entity, backup=backup)
        if (self.isError()): return None
        self.api_delete(entity[self.id_att])
        if (self.isError()): return None
        return self.create(entity, backup=False)

    def delete(self, idName: str = None, name: str = None, identifier: str = None, backup: bool = True) -> Union[dict, None]:
        entry = super().delete(idName=idName, name=name, identifier=identifier, backup=backup)
        if (self.isError()): return None
        self.api_delete(entry[self.id_att])
        if (self.isError()): return None
        return entry


###
### Factory Settings
###


class FactoryLoader:

    def __init__(self, service):
        self.service  = service
        self.path_dir = None

    def backup(self, entity : Union[str, list, None] = None, backup : bool = True, delete_all : bool = False) -> bool:
        if (not entity or entity.lower() == "all"):
            rc = True
            entities = StoreManager.list_store_entities()
            for entity in entities:
                res = self.delete_all(entity=entity, backup=backup, delete_all=delete_all)
                rc  = rc and res
            return rc
        if (entity.lower() not in StoreManager.list_store_entities(lower=True)):
            logger.error("Unknown entity : [" + str(entity) + "] service : [" + str(self.service) + "]")
            logger.error("Entities : [" + str(StoreManager.list_store_entities()) + "]" )
            return False
        server = StoreManager().getStore(entity.lower(), store_type=self.service)
        if (not server):
            # No StoreManager found
            logger.error("No Store Manager for entity : [" + str(entity) + "] service : [" + str(self.service) + "]")
            return False
        if (backup):
            logger.info("Backup for entity : [" + str(entity) + "] service : [" + str(self.service) + "]")
            server.backup()
            backup = False
        if (delete_all):
            logger.info("Delete All for entity : [" + str(entity) + "] service : [" + str(self.service) + "]")
            server.deleteAll(backup=backup)
        return True

    def delete_all(self, entity : Union[str, list, None] = None, backup : bool = False, delete_all : bool = True) -> bool:
        return self.backup(entity=entity, backup=backup, delete_all=delete_all)

    def b64file_handler(self, entry : dict, pathname : str = None) -> dict:
        if (not pathname):
            pathname = ut.get_cwd_directory()
        for key in entry:
            val = entry[key]
            # Handle 64 encoded string @b64file:<filenanme>:<b64 payload>
            if isinstance(val, str) and val.startswith("@b64file:"):
                b64data  = re.sub("@b64file:.*:", "", val)
                no_data = True if (b64data == "") else False
                filename = re.sub("@b64file:", "", val)
                filename = re.sub(":.*$", "", filename)
                filepathname = pathname + os.sep + filename
                logger.info("Loading b64file : "+filepathname)
                if (not ut.safeFileExist(filepathname)):
                    if (no_data):
                        raise AepCtlError("File not found : " + filepathname)
                    else:
                        logger.error("File not found : " + filepathname)
                        entry[key] = val
                else:
                    entry[key] = "@b64file:" + filename + ":" + ut.to_file_2_b64(filepathname)
            # Handle in sub-objects
            if isinstance(val, dict):
                entry[key] = self.b64file_handler(val, pathname)
        return entry

    def entry_loader(self, entry: dict, dir_path : str=None, entity_type: str=None, pathname : str=None, only_entity : str=None) -> Union[None, dict]:
        logger.info("Loading : \n" + ut.to_json(entry))
        if ((entity_type == None) and ("entity" in entry)):
            entity_type = entry["entity"]
        if (not entity_type):
            # No entity type Specified
            raise AepCtlError("No entity type specified for entry in ["+str(pathname)+"]: \n" + ut.to_json(entry))
        if ((only_entity and only_entity.lower() == "all")):
            pass
        elif ((only_entity) and (str(only_entity).lower() != str(entity_type).lower())):
            logger.error("Not loading entity type ["+str(entity_type)+"]: \n" + ut.to_json(entry))
            return None
        server = StoreManager().getStore(entity_type, self.service)
        if ("entry" in entry):
            entry = entry["entry"]
        if (StoreManager.get_id_att(entity_type) not in entry):
            entry[StoreManager.get_id_att(entity_type)] = "id"
        entry = self.b64file_handler(entry, dir_path)
        if ((server.exist(entry[StoreManager.get_id_att(entity_type)])) or
                (server.exist(entry[StoreManager.get_name_att(entity_type)]))):
            logger.info("Entry update : " + entry["id"])
            loaded = server.update(entry, backup=False)
        else:
            logger.info("Entry create : " + entry[StoreManager.get_id_att(entity_type)])
            loaded = server.create(entry, backup=False)
        logger.info("Entry Loaded : " + ut.to_json(loaded))
        return loaded

    def getDataStore(self, data : dict, pathname : str, entity : str = None):
        if (not data):
            # Invalid json or yaml
            raise AepCtlError("Invalid json or yaml Content : " + pathname)
        if (not self.service):
            # No Service Specified
            text = "No service specified for entry : " + str(pathname) + \
                   "\n Service : " + str(self.service) + \
                   "\n" + ut.to_json(data)
            raise AepCtlError(text)
        if (not entity and "entity" in data) :
            entity   = data["entity"]
        if (not entity):
            # No entity Specified
            text = "No entity specified for entry : " + str(pathname) + \
                   "\n entity : " + str(entity) + \
                   "\n" + ut.to_json(data)
            raise AepCtlError(text)
        server = StoreManager().getStore(entity, self.service)
        if (not server):
            # No StoreManager found
            text = "No Store Manager for entry : " + str(pathname) + \
                   "\n- entity  : " + str(entity) + \
                   "\n- service : " + str(self.service) + \
                   "\n" + ut.to_json(data)
            raise AepCtlError(text)
        return server

    def factory_loader(self, pathname, backup : bool=False, delete_all : bool=False, no_dir : bool=False, only_entity : str=None):
        if (backup):      self.backup(entity=only_entity)
        if (delete_all):  self.delete_all(entity=only_entity)
        abs_path = ut.get_abs_path(pathname)
        dir_path = ut.get_directory(abs_path)
        logger.info("Loading Path : " + abs_path)
        added_data = list()
        # Load a Directory
        if (ut.safeDirExist(pathname)):
            if (no_dir): raise AepCtlError("Cannot Load Directory (only files) : " + pathname)
            logger.info("Loading Directory : "  + pathname)
            # All json Files in directory
            logger.info("Scanning JSON Files in : "  + pathname)
            for file in ut.safeListFiles(pdir=pathname, file_ext=".json", keepExt=True):
                added_data = added_data + self.factory_loader(file)
            # All yaml Files in directory
            logger.info("Scanning YAML Files in : "  + pathname)
            for file in ut.safeListFiles(pdir=pathname, file_ext=".yaml", keepExt=True):
                added_data = added_data + self.factory_loader(file)
            return added_data
        # Load a Specific File
        if (not ut.safeFileExist(pathname)):
            raise AepCtlError("File not found : "  + pathname)
        if (ut.get_extension(pathname).lower() not in [".json", ".yaml"]):
            raise AepCtlError("Cannot Load File (only json or yaml files) : " + pathname)
        data = ut.loadFileData(pathname)
        if (not data):
            # Invalid json or yaml
            raise AepCtlError("Invalid json or yaml Content : "  + pathname)
        logger.debug("Loading : " + ut.to_json(data))
        # What's in the File ?
        if ("entity" in data) :  # This is the Entity Type
            # Single Entry of this type to store
            if ("entry" in data):
                rd = self.entry_loader(data["entry"], entity_type=data["entity"], dir_path=dir_path, only_entity=only_entity)
                if (rd) : added_data.append(rd)
            # Multiples Entries of same type to store
            elif ("entries" in data):
                for entry in data["entries"]:
                    rd = self.entry_loader(entry, entity_type=data["entity"], dir_path=dir_path, only_entity=only_entity)
                    if (rd): added_data.append(rd)
            else:
                raise AepCtlError("No \"entries\" in data : "+str(pathname)+"\n" + ut.to_json(data))
        elif ("entries" in data) :
            # Multiples Entries of different types to different stores
            for entry in data["entries"]:
                rd = self.entry_loader(entry, dir_path=dir_path, only_entity=only_entity)
                if (rd) : added_data.append(rd)
        else:
            for entity_type in StoreManager.list_store_entities():
                if ((entity_type.upper() in data) and (isinstance(data[entity_type.upper()], list))):  # Save Format
                    for entry in data[entity_type.upper()]:
                        rd = self.entry_loader(entry, dir_path=dir_path, only_entity=only_entity, entity_type=entity_type)
                        if (rd): added_data.append(rd)
                if ((entity_type in data) and (isinstance(data[entity_type], list))):  # Backup Format
                    for entry in data[entity_type]:
                        rd = self.entry_loader(entry, dir_path=dir_path, only_entity=only_entity, entity_type=entity_type)
                        if (rd): added_data.append(rd)
                if (entity_type in data) and ("entries" in data[entity_type]):  # Backup Format
                    for entry in data[entity_type]["entries"]:
                        rd = self.entry_loader(entry, dir_path=dir_path, only_entity=only_entity, entity_type=entity_type)
                        if (rd): added_data.append(rd)
        # Include other files
        if ("include" in data):
            for include_file in data["include"]:
                abs_file_path = dir_path + os.sep + include_file
                files = glob.glob(abs_file_path)  # Supporting Dir patterns like *.json
                for file in files:
                    if (not ut.safeFileExist(file)): raise AepCtlError("File Not Found : " + file)
                    logger.info("Including File : " + file)
                    added_data = added_data + self.factory_loader(file)
        # No Data
        if (len(added_data) == 0):
            raise AepCtlError("Invalid File Content (no entry found): " + pathname)
        # Data ))
        return added_data

FileStoreCache = dict()
RestStoreCache = dict()
Wso2StoreCache = dict()
TmfStoreCache  = dict()

###
### Data Stores
###

StoresCache = None
StoredDict  = None


class StoreManager():

    serviceList = ["applications", "userprofiles", "datastore", "filestore", "catalog", "subscription", "wso2"]

    def __init__(self, storefile=None):
        global STORES_FILE
        self.storefile = storefile if (storefile) else STORES_FILE
        self.store     = None
        self.stored    = None
        self.loadStores()

    def loadStores(self, storefile : str = None) -> Union[dict, None]:
        global StoresCache, StoredDict
        if (not storefile) : storefile = self.storefile
        if (StoresCache):
            self.store  = StoresCache
            self.stored = StoredDict
            self.storefile = storefile
            if (self.stored): return self.stored
        else :
            StoreManager.check_stores(storefile)
            self.storefile = storefile
            self.store = ut.loadDataFile(self.storefile)
            logger.info("Loaded Stores File : "+self.storefile)
        if (not self.store): return None
        self.stored = dict()
        for store in self.store["stores"] :
            self.stored[store["name"]] = store
        StoresCache = self.store
        StoredDict  = self.stored
        return self.stored

    def getStore(self, name : str, file : Union[bool, str] = False, store_type : str = "") -> Union[DataStoreInterface, None]:
        if (isinstance(file, str)):
            store_type = file
            file = True if (file.lower() in ["file", "fs", "filestore"]) else False
        if (isinstance(store_type, str)):
            if not (name.lower().startswith("ws")) :
                name = name if (store_type.lower() not in ["ws", "wso2"]) else "ws_"+name.lower()
        for store_key in self.stored :
            if (self.stored[store_key]["name"].lower()   == name.lower()): name = store_key
        if (name not in self.stored):
            for store_key in self.stored:
                if (self.stored[store_key]["entity"].lower() == name.lower()): name = store_key
        if (name not in self.stored): return None
        store = self.stored[name]
        if (store_type == "") :
            if (not file): store_type = "rest"
            else :
                store_type = "file"
                if (file.lower() in ["anme", "kite", "pagekite"]): store_type = "anme"
        if (store_type.lower() not in ["file" , "rest" , "wso2", "fs" , "ds" , "ws", "anme", "kite"]):
            logger.error("getStore : invalid store type : "+str(store_type))
            return None
        if (store_type.lower() in ["file", "fs"]):
            if (store["entity"] in FileStoreCache) :
                return FileStoreCache[store["entity"]]
            filestore = FileDataStore(entity_type=store["entity"], name_att=store["name_att"], desc_att=store["desc_att"], service=store["service"], schema=store["schema"])
            FileStoreCache[store["entity"]] = filestore
            return filestore
        elif (store_type.lower() in ["anme", "kite", "rest", "ds"]):  # ["anme", "kite"]
            if (store["entity"] in RestStoreCache):
                return RestStoreCache[store["entity"]]
            reststore = AnmeDataStore(entity_type=store["entity"], name_att=store["name_att"],
                                      desc_att=store["desc_att"], service=store["service"], schema=store["schema"])
            RestStoreCache[store["entity"]] = reststore
            return reststore
        elif (store_type.lower() in ["rest", "ds"]):
            if (store["entity"] in RestStoreCache):
                return RestStoreCache[store["entity"]]
            reststore = RestDataStore(entity_type=store["entity"], name_att=store["name_att"],
                                      desc_att=store["desc_att"], service=store["service"], schema=store["schema"])
            RestStoreCache[store["entity"]] = reststore
            return reststore
        elif (store_type.lower() in ["wso2", "ws"]) :
            if (name.lower() in ["users", "ws users", "wso2 users", "ws_users"]):
                name = "users"
            key = "wso2_" + name
            if (key in Wso2StoreCache) :
                return Wso2StoreCache[key]
            elif (name.lower() in ["users",        "ws_users"]):        wso2store = Wso2UsersManager()
            elif (name.lower() in ["categories",   "ws_categories"]):   wso2store = Wso2CategoriesManager()
            elif (name.lower() in ["policies",     "ws_policies"]):     wso2store = Wso2PoliciesManager()
            elif (name.lower() in ["apis",         "ws_apis"]):         wso2store = Wso2ApisManager()
            elif (name.lower() in ["applications", "ws_applications"]): wso2store = Wso2ApplicationsManager()
            else:
                logger.error("getStore : invalid wso2 store name : " + str(name))
                return None
            Wso2StoreCache[key] = wso2store
            return wso2store

    @staticmethod
    def get_entity(entity : str) -> str:
        if (entity.lower().startswith("ws")) :
            entity = re.sub(" ", "_", entity.lower().rstrip("s")) + "s"
        entity = re.sub("^.. ", "", entity.lower().rstrip("s") + "s")
        return  entity

    @staticmethod
    def get_store_entity(entity : str) -> Union[str, None]:
        sm = StoreManager()
        entity = StoreManager.get_entity(entity)
        for store in sm.stored:
            if (entity.lower() == sm.stored[store]["entity"].lower()):
                return sm.stored[store]
        for store in sm.stored:
            if (entity.lower() == sm.stored[store]["name"].lower()):
                return sm.stored[store]
        return None

    @staticmethod
    def get_store_entity_attribute(entity : str, attribute : str) -> str:
        store = StoreManager.get_store_entity(entity)
        if (not store):
            logger.info("Invalid Entity : " + entity)
            return None
        if (attribute not in store) : return None
        return store[attribute] if store else None

    @staticmethod
    def list_store_entities(store_file : str = None, lower : bool = False, service : str = "fs") -> list:
        global STORES_FILE
        if (not store_file) : store_file = STORES_FILE
        stores = StoreManager.check_stores(store_file)
        entity_list = list()
        for store in stores["stores"]:
            if ((service.lower() in ["ws", "wso2"]) and (not store["service"].lower().startswith("wso2"))):
                continue
            if ((service.lower() not in ["ws", "wso2"]) and (store["service"].lower().startswith("wso2"))):
                continue
            entity_list.append(store["entity"].lower() if lower else store["entity"])
        return entity_list

    @staticmethod
    def store_get_schema(entity : str):
        return StoreManager.get_store_entity_attribute(entity, "schema")

    @staticmethod
    def store_get_service(entity : str):
        return StoreManager.get_store_entity_attribute(entity, "service")

    @staticmethod
    def check_stores(store_file : str = None):
        global STORES_FILE
        if (not store_file) : store_file = STORES_FILE
        if (not ut.safeFileExist(store_file)):
            logger.error("File not found : "    + store_file)                             # pragma: no cover
            raise Exception("File not found : " + store_file)                             # pragma: no cover
        stores    = ut.loadFileData(store_file)
        if (not stores):
            raise AepCtlError("Invalid json or yaml content : " + store_file)             # pragma: no cover
        if (("stores" not in stores)):
            raise AepCtlError("No \"stores\" in : " + store_file)                         # pragma: no cover
        for store in stores["stores"]:
            StoreManager.check_store_file(entry=store, factory=False)
        return stores

    @staticmethod
    def check_store_file(entry: dict, factory : bool = False):
        class Service(StrEnum):
            FILE = "file"
            REST = "rest"
            WSO2 = "wso2"
            TMF  = "tmf"
            ANME = "anme"
            CATALOG  = "catalog"
            PROFILES = "userprofiles"

        class Store(BaseModel):
            name     : str
            entity   : str
            entity_schema: str | None = Field(alias="schema")
            id_att   : str
            name_att : str
            desc_att : str | None = None
            service  : Service

        try :
            pass
            # store = Store(**entry)
        except Exception as e:
            raise e

        if (("service" not in entry)):
            raise AepCtlError("No \"service\" in entry : " + json.dumps(entry, indent=2))    # pragma: no cover
        if (("entity" not in entry)):
            raise AepCtlError("No \"entity\" in entry : " + json.dumps(entry, indent=2))     # pragma: no cover
        if (("name_att" not in entry)):
            raise AepCtlError("No \"name_att\" in entry : " + json.dumps(entry, indent=2))   # pragma: no cover
        if (("desc_att" not in entry)):
            raise AepCtlError("No \"desc_att\" in entry : " + json.dumps(entry, indent=2))   # pragma: no cover
        if (("schema" not in entry)):
            logger.error("No \"schema\" in entry : " + json.dumps(entry, indent=2))          # pragma: no cover
            # raise Exception("No \"schema\" in entry : " + json.dumps(entry, indent=2))     # pragma: no cover

        if (entry["service"].lower() not in StoreManager.serviceList):
            raise AepCtlError("Unknown \"service\" in entry : " + entry["service"])          # pragma: no cover
        if (factory):
            if (entry["entity"].lower() not in StoreManager.list_store_entities(lower=True)):
                raise AepCtlError("Unknown \"entity\" in entry : " + entry["entity"])        # pragma: no cover
            if (("entry" not in entry) and ("entries" not in entry)):
                raise AepCtlError("No \"entry\" or \"entries\" in entry : " + json.dumps(entry, indent=2))  # pragma: no cover
        return entry

    @staticmethod
    def get_openapi_file(entity: str) -> Union[str, None]:
        openapiFile = None
        service = StoreManager.store_get_service(entity=entity)
        if (not service):
            return None
        schema = StoreManager.store_get_schema(entity=entity)
        if (not schema):
            # Unknown Entity
            return None    # pragma: no cover
        if (service in ["catalog", "datastore"]):
            openapiFile = CONFIG_DIRECTORY + os.sep + "NEF_Catalog_DataModel" + os.sep + "NEF_Catalog_DataModel_API.yaml"
        if (service in ["applications", "userprofiles"]):
            openapiFile = CONFIG_DIRECTORY + os.sep + "NEF_ApplicationUserProfile_DataModel" + os.sep + "NEF_ApplicationUserProfile_DataModel_API.yaml"
        return (openapiFile)

    @staticmethod
    def get_name_att(entity: str) -> Union[str, None]:
        return StoreManager.get_store_entity_attribute(entity, "name_att")

    @staticmethod
    def get_id_att(entity: str) -> Union[str, None]:
        return StoreManager.get_store_entity_attribute(entity, "id_att")

    @staticmethod
    def get_desc_att(entity: str) -> Union[str, None]:
        return StoreManager.get_store_entity_attribute(entity, "desc_att")

    @staticmethod
    def get_template(entity: str) -> Union[dict, None]:
        schema = StoreManager.get_schema(entity)
        if (schema):
            return ut.ObjectReader().templateObjectForThisSchema(schema)
        return None

    @staticmethod
    def get_schema_file(entity: str) -> Union[str, None]:
        entity = StoreManager.get_entity(entity)
        schemaFile = None
        service = StoreManager.store_get_service(entity=entity)
        if (not service):
            return None
        schema = StoreManager.store_get_schema(entity=entity)
        if (not schema):
            # Unknown Entity
            return None   # pragma: no cover
        if (service in ["catalog", "datastore"]):
            schemaFile = CONFIG_DIRECTORY + os.sep + "NEF_Catalog_DataModel" + os.sep + "_Schemas" + os.sep + schema + ".json"
        if (service in ["applications", "userprofiles"]):
            schemaFile = CONFIG_DIRECTORY + os.sep + "NEF_ApplicationUserProfile_DataModel" + os.sep + "_Schemas" + os.sep + schema + ".json"
        return (schemaFile)

    @staticmethod
    def check_schema(entry: dict, entity: str):
        entity = StoreManager.get_entity(entity)
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
            logger.error("Entity : " + str(entity) + " : \n" + json.dumps(entry, indent=2) + "\n" + str(e))
            return str(e)

    @staticmethod
    def get_schema(entity: str) -> Union[None, dict]:
        schemaFile = StoreManager.get_schema_file(entity)
        if (not schemaFile):
            return None  # pragma: no cover
        return ut.loadFileData(schemaFile)

    @staticmethod
    def get_openapi(entity: str) -> Union[None, dict]:
        openApiFile = StoreManager.get_openapi_file(entity)
        if (not openApiFile):
            return None
        return ut.loadFileData(openApiFile)

    @staticmethod
    def get_description(entity: str, idName : str):
        resource = StoreManager.get_entity(entity)
        service  = re.sub(" .*$", "", str(entity))
        store = StoreManager().getStore(name=resource, store_type=service)
        if (not store) : return "No Store / Description"
        return store.descByIdname(idName)

    @staticmethod
    def get_identifier(entity: str, idName : str):
        resource = StoreManager.get_entity(entity)
        service  = re.sub(" .*$", "", str(entity))
        file_service = True if (service.lower() == "fs") else False
        store = StoreManager().getStore(name=resource, file=file_service)
        if (not store) : return "No Store / Identifier"
        return store.idByName(idName)

    @staticmethod
    def get_name(entity: str, idName : str):
        resource = StoreManager.get_entity(entity)
        service  = re.sub(" .*$", "", str(entity))
        file_service = True if (service.lower() == "fs") else False
        store = StoreManager().getStore(name=resource, file=file_service)
        if (not store) : return "No Store / Name"
        return store.nameById(idName)

    @staticmethod
    def get_ressources(service: str) -> list:
        global STORES_FILE
        store_file = STORES_FILE
        stores = StoreManager.check_stores(store_file)
        entity_list = list()
        for store in stores["stores"]:
            if (service.lower() == store["service"].lower()):
                entity_list.append(store["entity"].replace("WS_", "").replace("ws_", ""))
        return entity_list

    @staticmethod
    def store_back_up(service: str="file", resource : str="all", operation="unknown", directory : str = None):
        global BACKUP_DIRECTORY
        if ((not directory) or (directory.strip() == "")): directory = BACKUP_DIRECTORY
        filename  = directory + os.sep + ut.safeTimestamp() + "_" + service.lower() + "_" + resource.lower() + "_stores.json"
        logger.info("BackUp File : " + filename)
        return StoreManager.store_save(service=service, resource=resource, save_file=filename, operation="back_up "+operation)

    @staticmethod
    def store_save(service: str="file", resource : str="all", save_file : str=None, operation="save"):
        resources = list()
        if (resource == "all"):
            resources = StoreManager.list_store_entities(service=service)
        elif (resource.lower() in StoreManager.list_store_entities(lower=True, service=service)):
            resources.append(resource)
        else:
            logger.error("Save : Unknown Resource : "+resource)
            return None
        all_data = dict()
        for res in resources :
            server = StoreManager().getStore(res, store_type=service)
            all_data[res] = server.list()
        sys_data = ut.get_sys()
        details = { "operation" : operation, "service" : service, "resources" : resources,
                    "timestamp" : ut.timestamp(), "configuration": ut.getCurrentConfiguration().getAsData(),
                    "status" : "success"   , "system" : sys_data, "filename" : save_file}
        all_data["__details__"] = details
        ut.saveJsonFile(all_data, save_file)
        return ut.to_json(details)

    @staticmethod
    def store_delete(service: str="file", resource : str="all", operation="delete", backup : bool = False):
        resources = list()
        if (resource == "all"):
            resources = StoreManager.list_store_entities(service=service)
        elif (resource.lower() in StoreManager.list_store_entities(lower=True, service=service)):
            resources.append(resource)
        else:
            logger.error("Delete : Unknown Resource : "+resource)
            return None
        all_data = dict()
        for res in resources :
            server = StoreManager().getStore(res, store_type=service)
            all_data[res] = server.deleteAll(backup=backup)
        sys_data = ut.get_sys()
        details = { "operation" : operation, "service" : service, "resources" : resources,
                    "timestamp" : ut.timestamp(), "configuration": ut.getCurrentConfiguration().getAsData(),
                    "status" : "success"   , "system" : sys_data}
        all_data["__details__"] = details
        return ut.to_json(all_data)

    @staticmethod
    def store_delete_all(service="file", operation : str ="delete_all"):
        StoreManager.store_back_up(service=service, resource="all", operation=operation)
        data = StoreManager.store_delete(service=service, resource="all", operation=operation, backup=False)
        logger.info("Delete All Service : " + service)
        return data

    @staticmethod
    def copy_store(serviceFrom : str, serviceTo : str, operation : str="copy_store", delete_all : bool = False):
        logger.info("copy_store From : " + serviceFrom + " To : " + serviceTo)
        StoreManager.store_back_up(service=serviceTo, resource="all", operation=operation)
        data = StoreManager.store_back_up(service=serviceFrom, resource="all", operation=operation)
        if (isinstance(data, str)) : data = ut.loadDataContent(data)
        if (not data):
            return None
        if (delete_all):
            StoreManager.store_delete(service=serviceTo, resource="all", operation=operation, backup=False)
        filename = data["filename"]
        FactoryLoader(service=serviceTo).factory_loader(filename, backup=False, delete_all=False)
        return data


LOCAL_SERVICE     = ["LOCAL", "FILES", "FS"]
DATASTORE_SERVICE = ["AEP", "REST", "DS"]
WSO2_SERVICE      = ["WSO2", "APIG", "WS", "APIM"]
SERVICES          = LOCAL_SERVICE + DATASTORE_SERVICE + WSO2_SERVICE

#                          Providers    Articles    Categories    Collections    APIs    ApiBundles    UsagePolicies
AEP_CATALOG_RESSOURCES = ["PROVIDERS", "ARTICLES", "CATEGORIES", "COLLECTIONS", "APIS", "APIBUNDLES", "USAGEPOLICIES"]
AEP_CATALOG_RESSOURCES = StoreManager().get_ressources("catalog")
#                                            Accounts    Services    Contacts    Roles    Industries    UseCases    Subscriptions
AEP_APPLICATION_USER_PROFILES_RESSOURCES = ["ACCOUNTS", "SERVICES", "CONTACTS", "ROLES", "INDUSTRIES", "USECASES", "SUBSCRIPTIONS"]
AEP_APPLICATION_USER_PROFILES_RESSOURCES = StoreManager().get_ressources("userprofiles")

AEP_RESSOURCES = AEP_CATALOG_RESSOURCES + AEP_APPLICATION_USER_PROFILES_RESSOURCES

#                WS_Apis WS_Policies WS_Categories  ### to do: PRODUCTS
APIM_RESSOURCES = ["APIS", "POLICIES", "CATEGORIES", "PRODUCTS"]
#                WS_Applications  ### to do: SUBSCRIPTIONS
DEVM_RESSOURCES = ["APPLICATIONS", "SUBSCRIPTIONS"]
#                WS_Users WS_Settings
ADM_RESSOURCES  = ["USERS", "SETTINGS"]
WSO2_RESSOURCES = APIM_RESSOURCES + DEVM_RESSOURCES + ADM_RESSOURCES
WSO2_RESSOURCES = StoreManager().get_ressources("wso2")

AEPCTL_COMMANDS_DISPLAY   = [ "HELP",      "VERBOSE",      "DS", "FS", "WS", "EXIT", "UI",      "BROWSER",       "COMMANDS"        , "BATCH" ]
AEPCTL_COMMANDS           = [ "HELP", "H", "VERBOSE", "V", "DS", "FS", "WS", "EXIT", "UI", "U", "BROWSER", "BR", "COMMANDS", "CMDS", "BATCH", "B"  ]
AEPCTL_RESSOURCES_DISPLAY = [ "CONFIG"]
AEPCTL_RESSOURCES         = [ "CONFIG", "CFG", "C" ]

"""

# Admin Wso2UsersManager

 add_user(self, userName: str, credential: str, roleList : str, requirePasswordChange : bool = False):
 list_users(self):
 delete_user(self, userName: str):
 is_user(self, userName: str):
 get_user_roles(self, userName: str):

# Publisher Wso2Manager

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


# Dev  Wso2SubscriptionsManager

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

    ONCE_UI = False

    @staticmethod
    def error(resource: str, command: str, message: str, help_text: str = None) -> str:
        text = ""
        if (resource != ""): text = text + resource.lower() + " "
        if (command  != ""): text = text + command.lower() + " "
        if (text     != ""): text = text + ": "
        error_text = text + message if (message) else text + " - Error."
        logger.info(error_text)
        ut.Term.print_red(error_text)
        ut.Term.print_blue(help_text)
        return error_text

    @staticmethod
    def init() -> None:
        global AEPCTL_Configuration
        AEPCTL_Configuration = ut.init_Configuration(cfg_filename=AEPCTL_Configuration_FileName,  # Default File Name
                                                     cmd_line_arg=CONFIG_FILE,  # Command Line Arg. FileName
                                                     env_cfg_var="AEPCTL_CONFIGURATION",  # Env Var with the FileName
                                                     default_cfg=def_AEPCTL_Configuration,  # Default Configuration
                                                     tag="AEPCTL Configuration")

    @staticmethod
    def help(resource: str, commands, options=None) -> str:
        if ((resource == None) or (resource == "")):
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
    def list_commands(commands : dict, prefix : str = "") -> str:
        cmdlist = ""
        if (isinstance(commands, NestedCompleter)):
            commands = commands.options
        for command in commands:
            if (commands[command] == None):
                cmdlist = cmdlist + "\n" + prefix + " " + command
            if (isinstance(commands[command], dict)):
                cmdlist = cmdlist + "" + AepCtl.list_commands(commands[command], prefix + " " + command)
            if (isinstance(commands[command], NestedCompleter)):
                cmdlist = cmdlist + "" + AepCtl.list_commands(commands[command], prefix + " " + command)
            if (isinstance(commands[command], PathCompleter)):
                cmdlist = cmdlist + "\n" + prefix + " " + command + " " + "<PathCompleter>"
        return cmdlist

    @staticmethod
    def print(resource: str, data: Union[dict, str, list], idName: str = None) -> str:
        if (idName):
            name = str(resource).lower() + "/" + str(idName)
        else:
            name = str(resource).lower()
        if isinstance(data, dict):
            print_text = json.dumps(data, indent=2)
        elif isinstance(data, list):
            print_text = json.dumps(ut.SuperDict(data=data, name=resource).clean().get(resource), indent=2)
        else:
            print_text = str(data)
        logger.info(print_text)
        ut.Term.print_green(print_text)
        return print_text

    @staticmethod
    def browse(resource, entry, idName: str = "") -> str:  # pragma: no cover
        name = str(resource).lower() + " " + str(idName)
        utg.dataBrowserForm(data=ut.SuperDict(entry, name=name).clean(), style="TREE",
                            formats_choices=["Json", "Yaml", "Flat"], read_only=True,
                            name=name, index_prefix=resource.capitalize() + " ").run()
        return AepCtl.print(resource, entry, idName)

    @staticmethod
    def display(resource, entry, idName) -> str:  # pragma: no cover
        name = str(resource).lower() + " " + str(idName)
        utg.dataBrowserForm(data=ut.SuperDict(copy.deepcopy(entry), name=name).clean(), style="TREE",
                            formats_choices=["Json", "Yaml", "Flat"], read_only=True,
                            name=name, index_prefix=resource.capitalize() + " ").run()
        return AepCtl.print(resource, entry, idName)

    @staticmethod
    def handle_output(entry, resource, command, idName: str = "", fileName: str = None) -> str:
        logger.info("handle_output " + " command : " + command + " idName : " + idName + " fileName : " + str(fileName))
        yaml_text = ut.to_yaml(entry, indent=2)
        json_text = ut.to_json(entry, indent=2)
        if ("file" in idName.strip()) :
            fileName = re.sub("^file", "", idName.strip())
            idName = "file"
        if (command.upper() == "DISPLAY"):  # pragma: no cover
            AepCtl.display(resource, entry, resource.lower() + " - " + str(idName))
            return yaml_text
        elif (idName.upper() == "DISPLAY"):
            AepCtl.display(resource, entry, resource.lower() + " - " + str(idName))
            return json_text
        elif (idName.upper() == "JSON"):
            ut.Term.print_green(json_text)
            return json_text
        elif (idName.upper() == "YAML"):
            ut.Term.print_green(yaml_text)
            return yaml_text
        elif (idName.upper() in ["FILE"]):
            ut.saveYamlFile(entry, fileName)
            AepCtl.print(resource, "Yaml saved in : " + fileName)
            return yaml_text
        else:
            ut.Term.print_green(json_text)
            return json_text
            # ut.saveYamlFile(entry, idName)
            # AepCtl.print (resource, "Yaml saved in : " + idName)
            # return yaml_text
        return yaml_text

    @staticmethod
    def aepctlui():
        if (AepCtl.ONCE_UI):
            ut.Term.print_red("aepctlui only once - sorry (")
            return None
        else:
            AepCtl.ONCE_UI = True
            ut.Term.print_yellow("aepctlui")
            return aepctlui.start_aepctlui()

    @staticmethod
    def display_help():
        console = Console()
        with open("aepctl.md", "r+") as help_file:
            text = Markdown(help_file.read())
            console.print(str(text.markup))
            return str(text.markup)

    @staticmethod
    def display_config() -> str:
        config = str(ut.getCurrentConfiguration())
        ut.Term.print_green(config)
        return config

    @staticmethod
    def edit_config() -> str:
        config = str(ut.getCurrentConfiguration())
        new_config = ut.ObjectReader.readSimpleObject(config)
        ut.save_Configuration(None, new_config)
        ut.Term.print_green(ut.to_json(new_config))
        return new_config

    @staticmethod
    def prompt_list_to_dict(elist: list, append: dict = None) -> dict:
        ldc = copy.deepcopy(append) if (append) else dict()
        for elem in elist:
            ldc[elem.lower()] = None
        return ldc

    @staticmethod
    def batch(fileName):
        if (not ut.safeFileExist(fileName)):
            AepCtl.error("Batch - no such file : "+fileName)
            return None
        file  = open(fileName, 'r')
        lines = file.readlines()
        count = 0
        for line in lines:
            count += 1
            line = line.strip()
            if (line.startswith("#")) : continue
            logger.info(str(count)+" - "+line)
            AepCtl.main(line)
        return None

    policy_type = {"application", "custom", "advanced", "deny-policies", "subscription", "mediation"}

    wso2_commands = {
        "settings": {
            "help"    :  None,
            "list"    :  None,
            "get"     :  {"apim", "dev", "admin", "help"},
            "display" :  {"apim", "dev", "admin", "help"},
        },
        "apis": {
            "help"    :  None,
            "list"    :  {"entries", "names", "ids", "help"},
            "browse"  :  {"all", "help"},
            "get"     :  {"<id>", "<name/version>", "help"},
            "display" :  {"<id>", "<name/version>", "help"},
            "delete"  :  {"<id>", "<name/version>", "help"},
            "lifecycle" : { "created"    : { "<id>" , "<name/version>", "help"},
                           "publish"    : { "<id>" , "<name/version>", "help"},
                           "prototyped" : { "<id>" , "<name/version>", "help"},
                           "deprecated" : { "<id>" , "<name/version>", "help"},
                           "blocked"    : { "<id>" , "<name/version>", "help"},
                           "retired"    : { "<id>" , "<name/version>", "help"}
                          },
            "details" :  {"<id>", "all", "help"},
            "backup"  :  None,
        },
        "policies": {
            "help"    :  None,
            "list"    :  {"entries", "count", "names", "ids", "help"},
            "browse"  :  { "all", "help"},
            "get"     :  {"<id>", "help"},
            "display" :  {"<id>", "help"}
        },
        "products": {
            "help"    :  None,
            "list"    :  {"entries", "count", "names", "ids", "help"},
            "browse"  :  { "all", "help"},
            "get"     :  {"<id>", "help"},
            "display" :  {"<id>", "help"}
        },
        "categories": {
            "help"    :  None,
            "list"    :  {"entries", "names", "ids", "count", "help"},
            "browse"  :  { "all",   "help"},
            "get"     :  {"<name>", "help"},
            "display" :  {"<name>", "help"},
            "delete"  :  {"<name>", "help"},
            "create"  :  {"<name>": {"<description>"}},
            "update"  :  {"<name>": {"<description>"}},
            "backup"  :  None,
        },
        "applications": {
            "help"    :  None,
            "list"    :  {"entries", "names", "ids", "count", "help"},
            "browse"  :  { "all",   "help"},
            "get"     :  {"<name>", "help"},
            "display" :  {"<name>", "help"},
            "delete"  :  {"<name>", "help"},
            "keys"    :  {"<name>", "help"},
            "genkeys" :  {"<name>", "help"},
            "backup"  :  None,
        },
        "users": {
            "help"    :  None,
            "list"    :  { "entries", "names", "ids", "count", "roles", "help" },
            "browse"  :  { "all", "help"},
            "get"     :  { "<name>",  "help"  },
            "display" :  { "<name>",  "help"  },
            "delete"  :  { "<name>",  "help"  },
            "create"  :  { "apiCreator"    : { "<name>" },
                           "apiConsumer"   : { "<name>" },
                           "apiAdmin"      : { "<name>" },
                           "apiMonitoring" : { "<name>" },
                         },
            "backup"  :  None,
            "roles"   :  {"<name>", "help"},
        },
        "browser": { "publisher", "apim", "dev", "portal", "mgt", "console", "help"},
    }

    @staticmethod
    def handle_ws02_generic_command(storeManager : DataStoreInterface, arguments) -> Union[str, None]:

        logger.info("handle_ws02_generic_command")

        resource = arguments["RESSOURCE"]
        command  = arguments["COMMAND"]
        idName   = arguments["ID"]
        payload  = arguments["PAYLOAD"]

        if (command == "HELP"):  # help
            return AepCtl.help(resource.lower(), command, AepCtl.wso2_commands)
        if (command == "BACKUP"):  # back up
            res = StoreManager().store_back_up(resource=resource, service="wso2")
            return AepCtl.print(resource, res)
        if (command == "LIST"):  # users list
            if (idName.upper() in [ "COUNT" ]) :
                return AepCtl.print(resource.lower() + " count", str(storeManager.list(count=True)))
            if (idName.upper() in [ "ROLES", "ROLE" ]) :
                return AepCtl.print(resource.lower() + " roles", apiRoles)
            if (idName.upper() in [ "NAMES", "NAME"]):
                nlist = storeManager.list(names=True)
                return AepCtl.print(resource.lower(), nlist)
            if (idName.upper() in [ "IDS", "ID" ]):
                nlist = storeManager.list(ids=True)
                return AepCtl.print(resource.lower(), nlist)
            return AepCtl.print(resource.lower(), storeManager.list())
        if (command == "BROWSE"):  # users list
            entry_list = list()
            return AepCtl.browse(resource.lower(), entry_list)
        if (command == "GET"):  # get user
            entry = storeManager.get(idName)
            return AepCtl.print(resource.lower(), entry, idName)
        if (command == "DISPLAY"):  # get user
            entry = storeManager.get(idName)
            return AepCtl.display(resource.lower(), entry, idName)
        if (command in [ "CREATE", "UPDATE" ] ):  # create user
            if (idName == "-p") :
                entry = ut.loadDataFile(payload)
            else:
                entry = ut.loadDataContent(idName)
            if (not entry): return AepCtl.error(resource.lower(), command, "Invalid JSON or YAML Entry : "+str(entry))
            entry = storeManager.save(entity=entry, backup=True)
            return AepCtl.print(resource.lower(), entry)
        if (command in [ "DELETE", "ERASE"  ] ):
            entry = storeManager.delete(idName)
            return AepCtl.print(resource.lower(), entry, idName)
        return None

    @staticmethod
    def handle_ws02_command(arguments):

        logger.info("handle_ws02_command")

        resource = arguments["RESSOURCE"]
        command  = arguments["COMMAND"]
        idName   = arguments["ID"]
        payload  = arguments["PAYLOAD"]

        usrMgr = Wso2UsersManager()
        apiMgr = Wso2Manager()
        devMgr = Wso2SubscriptionsManager()

        # All Help Levels
        if (command in ["HELP"]):  # <command>  help
            return AepCtl.help(None, AepCtl.wso2_commands)
        if (resource in ["HELP"]):  # <resource>  help
            return AepCtl.help(resource, AepCtl.wso2_commands)
        if (idName.upper() in ["HELP"]):  # <resource> <command> help
            return AepCtl.help(resource, command, AepCtl.wso2_commands)
        if (payload.upper() in ["HELP"]):  # <resource> <command> <idName> help
            return AepCtl.help(resource, command, AepCtl.wso2_commands)

        # Browser URLs
        if (command in ["BROWSER", "BR"]):  # Open Portal
            if (resource in ["HELP", "H", ""]):  # <browser>  help
                return AepCtl.help("browser", AepCtl.wso2_commands)
            if (idName.upper() in ["URL"]):  # <resource> <command> help
                res = Wso2Manager.browser(resource, openURL=False)
            elif (idName.upper() in ["OPEN", "BROWSE"]):  # <resource> <command> help
                res = Wso2Manager.browser(resource, openURL=True)
            else:  # <resource> <command> help
                res = Wso2Manager.browser(resource, openURL=True)
            return AepCtl.print("BROWSER", res, idName)

        # Settings
        if (resource == "SETTINGS"):
            if (command in ["LIST"]):  # settings list
                settings_List = ["PUBLISHER_PORTAL", "DEVELOPER_PORTAL", "ADMIN"]
                return AepCtl.print(resource, settings_List)
            if (command in ["GET", "DISPLAY"]):  # settings get|display
                if (idName.upper() in ["APIM", "PUBLISHER_PORTAL"]):
                    entry = apiMgr.getSettings()
                    if (apiMgr.isError()):  entry["error"] = apiMgr.getError()
                elif (idName.upper() in ["ADMIN", "WSO2"]):
                    entry = usrMgr.settings_get()
                    if (usrMgr.isError()):  entry["error"] = usrMgr.getError()
                elif (idName.upper() in ["DEV", "DEVELOPER_PORTAL"]):
                    entry = devMgr.settings_get()
                    if (devMgr.isError()):  entry["error"] = devMgr.getError()
                else:
                    return AepCtl.error(resource, command, "Unkown Settings : " + idName)
                if (command == "GET"):  # settings get
                    return AepCtl.print(resource, entry, idName)
                elif (command == "DISPLAY"):  # settings display
                    return AepCtl.display(resource, entry, idName)
            else:
                return AepCtl.error(resource, command, "Unkown command : " + command)

        # Publisher Wso2Manager
        if (resource == "APIS"):
            apiMgr = StoreManager().getStore(name="ws_apis", store_type="ws")
            # api_list(self, names: bool = False, names_versions: bool = False, ids: bool = False, versions: bool = False):
            # api_get(self, api_id):
            # api_details(self, api_id):
            # api_id_by_name(self, name: str, version: str = None) -> str:
            # api_create(self, api: str, swagger_file: str = None, publish: bool = False) -> str:
            # api_publish(self, api_id):
            # api_delete(self, api_id: str = None, name: str = None, version: str = None):
            if (command in ["DETAILS", "BROWSE"]):  # apis details/browse id|all
                details = apiMgr.api_details(api_id=idName)
                if (apiMgr.isError()): return AepCtl.error(resource, command, apiMgr.getError())
                return AepCtl.print(resource, details)
            if (command == "OPENAPI"):  # apis swagger
                swagger = apiMgr.api_get_swagger(api_id=idName)
                if (apiMgr.isError()): return AepCtl.error(resource, command, apiMgr.getError())
                return AepCtl.print(resource, swagger)
            if (command == "THUMBNAIL"):  # apis thumbnail
                thumbnail = apiMgr.api_get_thumbnail(api_id=idName)
                if (apiMgr.isError()): return AepCtl.error(resource, command, apiMgr.getError())
                return AepCtl.print(resource, thumbnail)
            if (command == "LIFECYCLE"):  # apis lifecycle
                state  = idName
                idName = payload
                res    = apiMgr.api_lifecycle(idName, state)
                if (apiMgr.isError()): return AepCtl.error(resource, command, apiMgr.getError())
                return AepCtl.print(resource, res)
            return AepCtl.handle_ws02_generic_command(apiMgr, arguments)
        if (resource == "POLICIES"):
            polMgr = StoreManager().getStore(name="ws_policies", store_type="ws")
            # "application", "custom", "advanced", "deny-policies", "subscription", "mediation"
            # policy_type(self, policy_type: str = "advanced"):
            # policy_list(self, policy_type: str = "advanced"):
            # policy_get(self, policy_id, policy_type: str = "advanced"):
            # policy_create(self, policy: str, policy_type: str = "advanced"):
            # policy_delete(self, policy_id, policy_type: str = "advanced"):
            return AepCtl.handle_ws02_generic_command(polMgr, arguments)
            if (command in ["LIST", "BROWSE"]):  # apis list
                elist = polMgr.list()
                if (apiMgr.isError()):
                    AepCtl.error(resource, command, polMgr.getError())
                elif (command == "LIST"):  # policies list
                    AepCtl.print(resource, elist)
                elif (command == "BROWSE"):  # policies browse
                    AepCtl.browse(resource, elist)
                return None
            if (command == "GET" or command == "DISPLAY"):  # policies get|display id|name
                entry = polMgr.get(policy_id=idName)
                if (command == "GET"):  # policies display
                    AepCtl.print(resource, entry, idName)
                elif (command == "DISPLAY"):  # policies display
                    AepCtl.display(resource, entry, idName)
                return None
        if (resource == "CATEGORIES"):
            catMgr = StoreManager().getStore(name="ws_categories", store_type="ws")
            # category_get(self, category_id):
            # category_list(self, service="admin"):
            # category_create(self, category: str):
            # category_delete(self, category_id):
            if (command in ["CREATE", "UPDATE"]):  # create user
                if (idName.lower() == "-p") :
                    entry = ut.loadDataFile(payload)
                else:
                    entry = dict()
                    entry["name"]        = idName
                    entry["description"] = payload
                if (not entry): return AepCtl.error(resource.lower(), command, "Invalid JSON or YAML Entry : " + str(entry))
                entry = catMgr.save(entity=entry, backup=True)
                return AepCtl.print(resource.lower(), entry)
            return AepCtl.handle_ws02_generic_command(catMgr, arguments)

        if (resource == "PRODUCTS"):
            # product_list(self):
            # product_get(self, product_id):
            # product_details(self, product_id):
            # product_delete(self, product_id):
            # product_create(self, api: str):
            if (command in ["LIST", "BROWSE"]):  # products list
                elist = apiMgr.product_list()
                if (apiMgr.isError()):
                    AepCtl.error(resource, command, apiMgr.getError())
                elif (command == "LIST"):  # products list
                    AepCtl.print(resource, elist)
                elif (command == "BROWSE"):  # products browse
                    AepCtl.browse(resource, elist)
                return None
            if (command == "GET" or command == "DISPLAY"):  # products get|display id|name
                entry = apiMgr.product_get(product_id=idName)
                if (command == "GET"):  # products display
                    AepCtl.print(resource, entry, idName)
                elif (command == "DISPLAY"):  # products display
                    AepCtl.display(resource, entry, idName)
                return None

        # Dev Wso2SubscriptionsManager
        if (resource == "APPLICATIONS"):
            appMgr = StoreManager().getStore(name="ws_applications", store_type="ws")
            # application_create(self, application: str):
            # application_list(self, names: bool = True):
            # application_get(self, app_id):
            # application_delete(self, app_id: str = None, name: str = None):
            # application_details(self, app_id):
            # application_id_by_name(self, name: str) -> str:
            # application_get_keys(self, app_id: str = None, app_name: str = None):
            # application_generate_keys(self, app_id: str = None, app_name: str = None):
            if (command == "KEYS" ):  # products get|display id|name
                keys = appMgr.application_get_keys(idName)
                AepCtl.print(resource, keys, idName)
            if (command == "GENKEYS" ):  # products get|display id|name
                keys = appMgr.application_generate_keys(idName)
                AepCtl.print(resource, keys, idName)
            return AepCtl.handle_ws02_generic_command(appMgr, arguments)
        if (resource == "SUBSCRIPTIONS"):
            # subscription_create(self, subscription: str):
            # subscription_list(self, applicationId: str = None, apiId: str = None):
            # subscription_get(self, subs_id):
            # subscription_delete(self, subs_id: str = None, name: str = None):
            # subscription_details(self, subs_id):
            # subscription_id(self, app_id: str, api_id: str) -> str:
            # subscribe(self,  app_id: str = None, app_name: str = None, api_id: str = None, api_name: str = None, api_version: str = None, policy: str = "Unlimited"):
            # unsubscribe(self, app_id: str = None, app_name: str = None, api_id: str = None, api_name: str = None, api_version: str = None):
            elist = devMgr.subscription_list()
            ut.Term.print_green(json.dumps(elist, indent=2))
            return None

        # Admin Wso2UsersManager
        if (resource == "USERS"):
            # Admin Wso2UsersManager
            # add_user(self, userName: str, credential: str, roleList: str, requirePasswordChange: bool = False):
            # list_users(self):
            # delete_user(self, userName: str):
            # is_user(self, userName: str):
            # get_user_roles(self, userName: str):
            """
            "help": None,
            "list"   :  { "users", "names", "roles", "count" },
            "get"    :  { "<name>",  "help"  },
            "backup" :  { "<name>",  "help"  },
            "delete" :  { "<name>",  "help"  },
            "create" :  { "apiCreator"    : { "<name>" },
                          "apiConsumer"   : { "<name>" },
                          "apiAdmin"      : { "<name>" },
                          "apiMonitoring" : { "<name>" },
                },
            """
            if (command in [ "CREATE", "UPDATE" ] ):  # create user
                if (idName == "-p") :
                    entry = ut.loadDataFile(payload)
                else:
                    entry = dict()
                    entry["name"] = payload
                    entry["role"] = idName
                if (not entry): return AepCtl.error(resource.lower(), command, "Invalid JSON or YAML Entry : " + str(entry))
                entry = usrMgr.save(entity=entry, backup=True)
                return AepCtl.print(resource.lower(), entry)
            return AepCtl.handle_ws02_generic_command(usrMgr, arguments)
        if (resource.upper() in ["ROLES", "ROLE"]):  # users roles
            return AepCtl.print("roles", apiRoles)

    handle_output_commands = {
        "json": None,
        "yaml": None,
        "display": None,
        "file": {"<filename>"},
    }

    ds_commands = {
        "help": None,
        "get": {
            "<id>"    : None,
            "<name>"  : None,
            "schema"  : handle_output_commands,
            "openapi" : handle_output_commands,
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
            "interactive"            : None,
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
        "openapi"      : handle_output_commands,
        "schema"       : handle_output_commands,
        "template"     : handle_output_commands,
        "load"    : {
            "delete_all" : PathCompleter(expanduser=True),  # SystemCompleter(),  # PathCompleter(expanduser=True),
            "merge"      : PathCompleter(expanduser=True),  # SystemCompleter(),  # PathCompleter(expanduser=True),
        },
        "save"         : PathCompleter(expanduser=True),  # SystemCompleter(),  # PathCompleter(expanduser=True),
        "backup"       : PathCompleter(expanduser=True),  # SystemCompleter(),  # PathCompleter(expanduser=True),
        "restore"      : {"<id/name>", "<name/version>", "all", "dir", "help"},
        "provision"    : {"<id/name>", "<name/version>", "all", "help"},
        "import"       : {"<id/name>", "<name/version>", "all", "dir", "help"},
        "export"       : {"<id/name>", "<name/version>", "all", "help"},
        "delete_all"   : None ,
    }

    @staticmethod
    def get_datastore_commands():
        ds_ressources = AepCtl.prompt_list_to_dict(AEP_RESSOURCES)
        for ds_ressource in ds_ressources:
            ds_ressources[ds_ressource] = AepCtl.ds_commands
        ds_ressources["help"]   = None
        ds_ressources["stores"] = None
        ds_ressources["load"] = {
            "delete_all" : PathCompleter(expanduser=True),  # SystemCompleter(),  # PathCompleter(expanduser=True),
            "merge"      : PathCompleter(expanduser=True),  # SystemCompleter(),  # PathCompleter(expanduser=True),
        }
        return ds_ressources

    @staticmethod
    def get_aep_commands():
        dcmd = AepCtl.prompt_list_to_dict(AEPCTL_COMMANDS_DISPLAY)
        dcmd["config"] = {"edit": None, "set": {"<param> <value>": None}, "get": {"<param>": None}}
        dcmd["batch"] = PathCompleter(expanduser=True)
        return dcmd

    FS_COMMANDS = ["LOAD", "SAVE", "IMPORT", "EXPORT", "BACKUP", "RESTORE", "DELETE_ALL", "PROVISION_WS"]

    @staticmethod
    def get_aep_completer(for_service : str = "all"):  # pragma: no cover
        dcmd = dict()
        if (for_service.lower() == "fs")  : dcmd = AepCtl.get_datastore_commands()
        if (for_service.lower() == "ds")  : dcmd = AepCtl.get_datastore_commands()
        if (for_service.lower() == "ws")  : dcmd = copy.deepcopy(AepCtl.wso2_commands)
        if (for_service.lower() == "aep") : dcmd = AepCtl.get_aep_commands()
        if (for_service.lower() == "all") :
            dcmd = AepCtl.get_aep_commands()
            dcmd["ws"] = copy.deepcopy(AepCtl.wso2_commands)
            dcmd["fs"] = AepCtl.get_datastore_commands()
            dcmd["ds"] = AepCtl.get_datastore_commands()
        return NestedCompleter.from_nested_dict(dcmd)

    @staticmethod
    def handle_datastore_command(arguments):

        logger.info("handle_datastore_command")

        resource = arguments["RESSOURCE"]
        command  = arguments["COMMAND"]
        idName   = arguments["ID"]
        service  = arguments["SERVICE"]
        payload  = arguments["PAYLOAD"]
        service  = "file" if (service in LOCAL_SERVICE) else "rest"

        if (command in ["HELP"]):  # <resource>  help
            return AepCtl.help(resource, AepCtl.get_datastore_commands())
        if (resource in ["HELP"]):  # <command> help
            return AepCtl.help(resource, AepCtl.get_datastore_commands())
        if (resource == "STORES"):
            return AepCtl.print(resource, str(StoreManager.list_store_entities()))
        if ((command == "") and (resource == "")):
            return AepCtl.error(resource, command, "No command nor resource specified.", AepCtl.help(resource, AepCtl.get_datastore_commands()))
        store = None
        if (resource != "all"):
            try:
                store = StoreManager().getStore(resource, file=service)
            except Exception as ex:
                return AepCtl.error(resource, command, "Store Access Error.", AepCtl.print("resources", str(ex).replace("\\n", "\n")))
            if (not store):
                return AepCtl.error(resource, command, "Invalid Resource.", ut.to_json(StoreManager.list_store_entities()))
        if (command in ["OPENAPI"]):
            openapi = StoreManager.get_openapi(entity=resource)
            return AepCtl.handle_output(openapi, resource, command, idName, fileName="OpenAPI_" + resource + ".yaml")
        elif (command in ["SCHEMA"]):
            schema = StoreManager.get_schema(entity=resource)
            return AepCtl.handle_output(schema, resource, command, idName, fileName="Schema_" + resource + ".yaml")
        elif (command in ["TEMPLATE", "NEW"]):
            template = StoreManager.get_template(entity=resource)
            return AepCtl.handle_output(template, resource, command, idName, fileName="Template_" + resource + ".yaml")
        elif (command in ["LIST", "BROWSE"]):
            if (resource == "STORES"):
                return AepCtl.print(resource, StoreManager.list_store_entities())
            entry_list = store.list(ids=(idName.lower() == "ids"), names=(idName.lower() == "names"), count=(idName.lower() == "count"))
            if (store.error()):
                return AepCtl.error(resource, command, store.error())
            if (command == "LIST"):
                return AepCtl.print(resource, entry_list, resource)
            if (command == "BROWSE"):
                return AepCtl.browse(resource, entry_list, resource)
        elif (command in ["GET", "DISPLAY"]):
            if (idName == ""):
                return AepCtl.error(resource, command, "No ID nor Name provided.")
            if (idName.upper() == "SCHEMA"):
                schema = StoreManager.get_schema(entity=resource)
                command = idName
                idName  = payload
                return AepCtl.handle_output(schema, resource, command, idName, fileName="Schema_" + resource + ".yaml")
            if (idName.upper() == "OPENAPI"):
                openapi = StoreManager.get_openapi(entity=resource)
                command = idName
                idName  = payload
                return AepCtl.handle_output(openapi, resource, command, idName, fileName="OpenAPI_" + resource + ".yaml")
            entry = store.get(idName)
            if (store.error()):         return AepCtl.error(resource, command, store.error())
            if (not entry):             return AepCtl.error(resource, command, "No such entry : " + idName)
            if (command == "GET"):      return AepCtl.print(resource, entry, idName)
            if (command == "DISPLAY"):  return AepCtl.display(resource, entry, idName)
        elif (command in ["DELETE"]):
            if (idName.upper() == "ALL") :
                entries = store.deleteAll()
                if (store.error()): return AepCtl.error(resource, command, store.error())
                return AepCtl.print(resource, entries)
            else:
                entry = store.delete(idName)
                if (store.error()): return AepCtl.error(resource, command, store.error())
                return AepCtl.print(resource, entry)
        elif (command in ["CREATE", "UPDATE"]):
            filename = payload
            entry     = None
            if (idName.upper()  == "INTERACTIVE"):
                schema = StoreManager.get_schema(resource)
                if (not schema):
                    return AepCtl.error(resource, command, "Cannot Get Schema for : " + resource)
                payload = ut.ObjectReader().readObjectForThisSchema(schema)
                if (not payload):
                    return AepCtl.error(resource, command, "Cannot Get Entry for : " + resource)
            else:
                if (ut.safeFileExist(filename)):
                    logger.info("Filename : " + filename)
                    payload = ut.loadFileData(filename)
                else:
                    logger.info("Payload : " + payload)
                    payload = ut.loadDataContent(payload)
                if (not payload):
                    return AepCtl.error(resource, command, "Cannot JSON/YAML Decode : " + filename)
            if (not isinstance(payload, dict)):
                return AepCtl.error(resource, command, "Cannot JSON/YAML Decode : " + filename)
            logger.info("Entry : \n" + json.dumps(payload, indent=2))
            if ((store.id_att in payload) and (store.exist(payload[store.id_att]))):
                command = "UPDATE"
            else:
                command = "CREATE"
            if (command == "UPDATE"):  entry = store.update(payload)
            if (command == "CREATE"):  entry = store.create(payload)
            if (store.error()):
                return AepCtl.error(resource, command, store.error())
            return AepCtl.print(resource, entry)
        elif (command in ["BACKUP"]):
            res = StoreManager().store_back_up(resource=resource, service=service, directory=idName)
            return AepCtl.print(resource, res)
        elif (command in ["LOAD"]):
            delete_all = False
            if (idName.lower() in ["deleteall", "delete_all", "reset"]):
                delete_all = True
                pathname = str(payload).strip()
                pathname = ut.get_cwd_directory()+os.sep+pathname
            elif (idName.lower() in ["nodelete", "no_delete", "append", "add", "update", "merge"]):
                delete_all = False
                pathname = str(payload).strip()
                pathname = ut.get_cwd_directory()+os.sep+pathname
            else :
                pathname = idName.strip()
            logger.info("Loading : " + pathname)
            logger.info("To      : " + service)
            res = FactoryLoader(service=service).factory_loader(pathname=pathname, delete_all=delete_all, backup=True, no_dir=True, only_entity=resource)
            return AepCtl.print(resource, res)
        elif (command in ["SAVE"]):
            pathname = ut.get_cwd_directory()+os.sep+str(idName).strip()
            pathname = ut.get_basename(pathname)+".json"
            logger.info("Saving : " + pathname)
            res = StoreManager.store_save(service=service, resource=resource, save_file=pathname)
            return AepCtl.print(resource, res)
        elif (command in ["EXTRACT"]):
            logger.info("Extracting : " + str(idName))
            wsp = Wso2Provisioning()
            res = wsp.extractWso2Apis(idName, dataStore=service)
            return AepCtl.print(resource, res)
        elif (command in ["DELETE_ALL"]):
            logger.info("Deleting All : " + str(service))
            res = StoreManager.store_delete_all(service, operation="delete all")
            return AepCtl.print(resource, res)
        elif (command in ["EXPORT"]):
            logger.info("Export : " + str(payload))
            res = StoreManager.copy_store(serviceFrom=service, serviceTo=payload, operation="export " + payload)
            return AepCtl.print(resource, res)
        elif (command in ["IMPORT"]):
            logger.info("Import : " + str(payload))
            res = StoreManager.copy_store(serviceFrom=payload, serviceTo=service, operation="Import " + payload)
            return AepCtl.print(resource, res)
        elif (command in ["PROVISION"]):
            if (resource.upper() not in ["APIS", "CATEGORIES", "SERVICES", "CONTACTS", "USECASES", "SUBSCRIPTIONS", "USAGEPOLICIES"]):
                return AepCtl.error(resource, command, "Invalid Resource to Provision : " + resource, AepCtl.help(resource, AepCtl.get_datastore_commands()))
            wsp = Wso2Provisioning()
            logger.info("Provisioning " + resource + " : " + str(idName))
            if (resource.upper() == "APIS"):
                res = wsp.provisionAPI(idName, dataStore=service)
                return AepCtl.print(resource, res)
            if (resource.upper() == "CATEGORIES"):
                res = wsp.provisionCategory(idName, dataStore=service)
                return AepCtl.print(resource, res)
            if (resource.upper() == "SERVICES"):
                res = wsp.provisionService(idName, dataStore=service)
                return AepCtl.print(resource, res)
            if (resource.upper() == "CONTACTS"):
                res = wsp.provisionContact(idName, dataStore=service)
                return AepCtl.print(resource, res)
            if (resource.upper() in ["USECASES", "SUBSCRIPTIONS" ]):
                res = wsp.subscribeServiceToApi(idName, dataStore=service)
                return AepCtl.print(resource, res)
            if (resource.upper() in ["POLICIES", "USAGEPOLICIES"]):
                res = wsp.provisionPolicy(idName, dataStore=service)
                return AepCtl.print(resource, res)
        else:
            return AepCtl.error(resource, command, "Invalid Command.", AepCtl.help(resource, AepCtl.get_datastore_commands()))
        return None

    @staticmethod
    def handle_command(arguments):

        resource = arguments["RESSOURCE"].upper() if (("RESSOURCE" in arguments) and (arguments["RESSOURCE"])) else ""
        command  = arguments["COMMAND"].upper()   if (("COMMAND" in arguments)   and (arguments["COMMAND"]))   else ""
        idName   = arguments["ID"]                if (("ID" in arguments)        and (arguments["ID"]))        else ""
        service  = arguments["SERVICE"].upper()   if (("SERVICE" in arguments)   and (arguments["SERVICE"]))   else "REST"
        entry    = arguments["PAYLOAD"]           if (("PAYLOAD" in arguments)   and (arguments["PAYLOAD"]))   else idName
        entry    = re.sub("\\\"", '"', entry)
        arguments["PAYLOAD"] = entry
        if (    (resource.upper() in AEPCTL_COMMANDS) or
                (command.upper()  in AEP_RESSOURCES) or
                (command.upper()  in WSO2_RESSOURCES)):
            tmp_res  = command
            command  = resource.upper()
            resource = tmp_res.upper()
            logger.info("Swapped Resource=" + str(resource) + " Command=" + str(command))
        resource = resource.strip()
        command  = command.strip()

        arguments["RESSOURCE"] = resource
        arguments["COMMAND"]   = command
        arguments["ID"]        = idName
        arguments["SERVICE"]   = service
        arguments["PAYLOAD"]   = entry

        if ((service.upper() in ["FS", "DS", "FILE", "REST"]) and (resource in AepCtl.FS_COMMANDS)):
            arguments["PAYLOAD"]   = arguments["ID"]
            arguments["ID"]        = arguments["COMMAND"]
            arguments["COMMAND"]   = arguments["RESSOURCE"]
            arguments["RESSOURCE"] = "all"
            entry    = idName
            idName   = command
            command  = resource
            resource = "all"

        logger.info("SERVICE   = " + str(service))
        logger.info("RESSOURCE = " + str(resource))
        logger.info("COMMAND   = " + str(command))
        logger.info("IDNAME    = " + str(idName))
        logger.info("PAYLOAD   = " + str(entry))

        if (resource.upper() in ["CONFIG", "CFG", "C"]):
            if (command.upper() in [""]):
                return AepCtl.display_config()
            elif (command.upper() in ["SET"]):
                return ut.set_Configuration(None, p_key=idName, p_value=entry)
            elif (command.upper() in ["GET", "PARAM"]):
                return ut.get_Configuration(None, p_key=idName)
            elif (command.upper() in ["EDIT", "CFG", "C"]):
                return AepCtl.edit_config()
            else:
                return AepCtl.edit_config()
        elif((command.upper() in ["HELP", "H"]) and (resource.upper() == "")):
            return AepCtl.display_help()
        elif (command.upper() in ["COMMANDS", "COMMAND", "CMD", "CMDS"]):
            cmdlist = AepCtl.list_commands(AepCtl.get_aep_completer((service if (resource == "") else resource).upper()))
            ut.Term.print_blue(cmdlist)
            return cmdlist
        elif (command.upper() in ["VERBOSE", "V"]):
            return ut.Verbose.swap_verbose()
        elif (command.upper() in ["UI", "U"]):
            return Thread(target=AepCtl.aepctlui).start()
        elif (command.upper() in ["BATCH", "B"]):
            return AepCtl.batch(resource)

        elif (service.upper() in WSO2_SERVICE):
            return AepCtl.handle_ws02_command(arguments)
        elif (service.upper() in LOCAL_SERVICE):
            return AepCtl.handle_datastore_command(arguments)
        elif (service.upper() in DATASTORE_SERVICE):
            return AepCtl.handle_datastore_command(arguments)
        elif (resource.upper() in AEP_RESSOURCES):
            return AepCtl.handle_datastore_command(arguments)
        elif (resource.upper() in WSO2_RESSOURCES):
            return AepCtl.handle_ws02_command(arguments)
        else:
            ut.Term.print_red("Unknown Command or Resource : " + command + " " + resource)
            ut.Term.print_green(AepCtl.read_command_line_args(None, p_usage=True))
            return None

    ###
    ### Prompt Completion
    ###

    @staticmethod
    def interactive_prompt():  # pragma: no cover
        ut.Verbose.set_verbose(False, silent=True)
        current_context = "ds"
        try:
            history = FileHistory(filename=AEPCTL_HOME_DIR + os.sep + "history")
            session = PromptSession(history=history)
        except Exception as e:
            # No proper terminal support
            print(str(e))
            session = None
        command = ""
        ctrl_c  = False
        while command != "exit":
            if (session):
                if (current_context == "fs"): text = AEPCTL_PROMPT + colored("fs", "red") + " > "  # Not compatible with prompt ?
                if (current_context == "fs"): text = HTML(AEPCTL_PROMPT + " <IndianRed>"      + current_context + "</IndianRed>" + " > ")
                if (current_context == "ds"): text = HTML(AEPCTL_PROMPT + " <MediumSeaGreen>" + current_context + "</MediumSeaGreen>" + " > ")
                if (current_context == "ws"): text = HTML(AEPCTL_PROMPT + " <DeepSkyBlue>"    + current_context + "</DeepSkyBlue>" + " > ")
                try:
                    command = session.prompt(text, completer=AepCtl.get_aep_completer(current_context), complete_while_typing=True)
                    ctrl_c  = False
                except KeyboardInterrupt :   # Capture CTRL-C Reset Line
                    if (ctrl_c) : return     # Double CTRL-C Exit
                    ctrl_c = True
                    continue
            else:
                if (current_context == "fs"): text = AEPCTL_PROMPT + colored(current_context, "red")   + " > "  # Not compatible with prompt ?
                if (current_context == "ds"): text = AEPCTL_PROMPT + colored(current_context, "green") + " > "  # Not compatible with prompt ?
                if (current_context == "ws"): text = AEPCTL_PROMPT + colored(current_context, "blue")  + " > "  # Not compatible with prompt ?
                command = input(AEPCTL_PROMPT + " " + current_context + " > ")
            logger.info("Prompt command : " + command)
            command = command.strip()
            if (command in ["", " "]):
                continue
            if (command.upper() in ["EXIT", "X", "QUIT", "Q", "BYE", "B"]):
                return None
            if (command.upper() in ["VERBOSE", "V", "DEBUG", "D"]):
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
            res = AepCtl.main(command, interactive=True)
            logger.debug(res)
            # print(str(res))


    ###
    ### Main
    ###

    @staticmethod
    def read_command_line_args(argv, p_usage : bool = False) -> Union[str, dict, None]:
        global CONFIG_FILE

        usage = """
    Usage: -h -v -u -c <ConfigurationFile.json> [<service>] [<resource>] [<command>] [<identifier>] [<payload>] [-p <PayloadFile.json>] 
           -h --help        : Usage help 
           -v --verbose     : Verbose     
           -u --ui          : User Interface     
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
    Commands  : """ + str(AEPCTL_COMMANDS_DISPLAY) + """  
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
        cl_args["SERVICE"]        = None
        cl_args["CONFIG_FILE"]    = None
        cl_args["VERBOSE"]        = False

        try:
            opts, args = getopt.getopt(argv, "hvuc:p:s:fw", ["help", "verbose", "ui", "debug",  "config=", "payload=", "service=", "filestore", "wso2"])
        except getopt.GetoptError as e:
            ut.Term.print_yellow("Command Line Arguments : " + str(argv))
            ut.Term.print_red("GetoptError : " + str(e))
            ut.Term.print_blue(usage)
            return None
        for opt, arg in opts:
            if opt.lower() in ("-h", "--help"):
                ut.Term.print_blue(usage)
                return None
            elif opt.lower() in ("-v", "-verbose"):
                cl_args["VERBOSE"] = True
                ut.Term.setVerbose(True)
                continue
            elif opt.lower() in ("-u", "--ui"):
                aepctlui.MainGUI().run()
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
                if (command.upper() not in AEPCTL_COMMANDS):
                    ut.Term.print_red("Invalid Command : "   + str(service))
                    ut.Term.print_green("Known Commands  : " + str(AEPCTL_COMMANDS))
                    ut.Term.print_blue(usage)
                    return None
                cl_args["COMMAND"] = command.upper()
                continue
            else :
                ut.Term.print_red("Invalid Command Line Option : " + opt)
                ut.Term.print_blue(usage)
                return None
        for arg in args :
            if   (arg.upper() in SERVICES)  :
                if (not cl_args["SERVICE"]):
                    cl_args["SERVICE"] = arg
                else:
                    cl_args["ID"] = arg
                continue
            if   (not cl_args["RESSOURCE"]) : cl_args["RESSOURCE"] = arg
            elif (not cl_args["COMMAND"])   : cl_args["COMMAND"]   = arg
            elif (not cl_args["ID"])        : cl_args["ID"]        = arg
            elif (not cl_args["PAYLOAD"])   : cl_args["PAYLOAD"]   = arg
            else : cl_args["PAYLOAD"] = cl_args["PAYLOAD"] + " " + arg
            continue
        if (not cl_args["SERVICE"]): cl_args["SERVICE"] = "ds"
        # logger.info("Command Line Args : \n" + json.dumps(cl_args, indent=3))
        return cl_args

    @staticmethod
    def set_aepctl_dirs(P_AEPCTL_ROOT_DIR: str, P_AEPCTL_WORK_DIR: str):
        global CONFIG_DIRECTORY, TMP_DIRECTORY, DATA_DIRECTORY, TEST_DIRECTORY
        global LOGS_DIRECTORY, SCRIPTS_DIRECTORY, BACKUP_DIRECTORY, STORE_DIRECTORY
        global STORES_FILE, CONFIG_FILE
        if (not P_AEPCTL_ROOT_DIR): P_AEPCTL_ROOT_DIR = AEPCTL_ROOT_DIR
        if (not P_AEPCTL_WORK_DIR): P_AEPCTL_WORK_DIR = AEPCTL_WORK_DIR
        CONFIG_DIRECTORY  = P_AEPCTL_ROOT_DIR + os.sep + "etc"
        DATA_DIRECTORY    = P_AEPCTL_ROOT_DIR + os.sep + "data"
        TMP_DIRECTORY     = P_AEPCTL_ROOT_DIR + os.sep + "tmp"
        TEST_DIRECTORY    = P_AEPCTL_ROOT_DIR + os.sep + "tests"
        LOGS_DIRECTORY    = P_AEPCTL_ROOT_DIR + os.sep + "logs"
        SCRIPTS_DIRECTORY = P_AEPCTL_ROOT_DIR + os.sep + "scripts"
        BACKUP_DIRECTORY  = P_AEPCTL_ROOT_DIR + os.sep + "backup"
        STORE_DIRECTORY   = P_AEPCTL_WORK_DIR + os.sep + "store"
        STORES_FILE       = P_AEPCTL_ROOT_DIR + os.sep + "etc" + os.sep + "stores.json"

    @staticmethod
    def main(argv, interactive : bool = False):
        global AEPCTL_Configuration

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        args = AepCtl.read_command_line_args(argv)

        if (args == None):
            return None

        if (not interactive):
            ut.Verbose.set_verbose(p_verbose=args["VERBOSE"], silent=True)
        else:
            ut.Verbose.init_verbose(False)

        logger.info("Command Line Arguments : " + str(argv))
        logger.info("Command Line Args : \n" + json.dumps(args, indent=3))

        AEPCTL_Configuration = ut.init_Configuration(cfg_filename=AEPCTL_Configuration_FileName,  # Default Config FileName
                                                     cmd_line_arg=CONFIG_FILE,  # Command Line Arg. Config FileName
                                                     env_cfg_var="AEPCTL_CONFIGURATION",  # Env Var with the Config FileName
                                                     default_cfg=def_AEPCTL_Configuration,  # Default Configuration
                                                     tag="AEPCTL Configuration")

        CFG_AEPCTL_ROOT_DIR = AEPCTL_Configuration.get("AEPCTL_DIRECTORY")
        CFG_AEPCTL_WORK_DIR = AEPCTL_Configuration.get("AEPCTL_DIRECTORY")
        CFG_AEPCTL_HOME_DIR = AEPCTL_HOME_DIR
        AepCtl.set_aepctl_dirs(CFG_AEPCTL_ROOT_DIR, CFG_AEPCTL_WORK_DIR)
        logger.info("AEPCTL_HOME_DIR  : " + str(CFG_AEPCTL_HOME_DIR))
        logger.info("AEPCTL_ROOT_DIR  : " + str(CFG_AEPCTL_ROOT_DIR))
        logger.info("AEPCTL_WORK_DIR  : " + str(CFG_AEPCTL_WORK_DIR))
        # os.chdir(AEPCTL_HOME_DIR)

        return AepCtl.handle_command(args)


if __name__ == '__main__':    # pragma: no cover
    if (len(sys.argv[1:]) == 0):
        # No arguments : interactive session
        AepCtl.interactive_prompt()
    else:
        # Arguments : one time command
        AepCtl.main(argv=sys.argv[1:], interactive=False)


###
### Unit Tests
###


class TestMain(unittest.TestCase):     # pragma: no cover

    def setUp(self) -> None:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def testCommandLineArguments(self):
        AepCtl.main("-v fs providers list names")

    def testInteractive(self):
        command = input(AEPCTL_PROMPT + " > ")
        while command != "exit" :
            res = AepCtl.main(command, interactive=True)
            logger.debug(res)
            command = input(AEPCTL_PROMPT + " > ")


# Need WSO2 Server to test this
class TestWso2Manager(unittest.TestCase):    # pragma: no cover

    def setUp(self) -> None:
        global AEPCTL_Configuration
        AEPCTL_Configuration = ut.init_Configuration(cfg_filename=AEPCTL_Configuration_FileName,  # Default File Name
                                                     cmd_line_arg=CONFIG_FILE,  # Command Line Arg. FileName
                                                     env_cfg_var="AEPCTL_CONFIGURATION",  # Env Var with the FileName
                                                     default_cfg=def_AEPCTL_Configuration,  # Default Configuration
                                                     tag="AEPCTL Configuration")
        self.userManager  = Wso2UsersManager()
        self.apiManager   = Wso2ApisManager()
        self.devManager   = Wso2SubscriptionsManager()
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def test_userManager(self):  # Need WSO2 server to test this
        self.userManager.delete_user("apicreator")
        self.assertEqual(False,             self.userManager.is_user("apicreator"))
        self.assertNotIn("apicreator",      self.userManager.list_users())
        self.assertIsNotNone(self.userManager.add_user(userName="apicreator", role="apicreator", requirePasswordChange=True))
        self.assertIn("apicreator",         str(self.userManager.list_users()))
        self.assertIn("apicreator",         str(self.userManager.get_user("apicreator")))
        self.assertEqual(True,              self.userManager.is_user("apicreator"))
        self.assertIn("Internal/creator",   str(self.userManager.get_user_roles("apicreator")))
        self.assertIsNotNone(self.userManager.delete_user("apicreator"))
        self.assertNotIn("apicreator",      self.userManager.list_users())
        self.assertEqual(False,             self.userManager.is_user("apicreator"))

        self.userManager.delete_user("apiconsumer")
        self.assertEqual(False,             self.userManager.is_user("apiconsumer"))
        self.assertNotIn("apiconsumer",     self.userManager.list_users())
        self.assertIsNotNone(self.userManager.add_user(userName="apiconsumer", role="apiconsumer", requirePasswordChange=True))
        self.assertIn("apiconsumer",        str(self.userManager.list_users()))
        self.assertIn("apiconsumer",        str(self.userManager.get_user("apiconsumer")))
        self.assertEqual(True,              self.userManager.is_user("apiconsumer"))
        self.assertIn("apim_devportal",     str(self.userManager.get_user_roles("apiconsumer")))
        self.assertIsNotNone(self.userManager.delete_user("apiconsumer"))
        self.assertNotIn("apiconsumer",     self.userManager.list_users())
        self.assertEqual(False,             self.userManager.is_user("apiconsumer"))

        user = { "name" : "apiadmin" , "role" : "apiadmin"}
        self.userManager.delete_user(user)
        self.assertEqual(False,          self.userManager.is_user(user))
        self.assertNotIn("apiadmin",     self.userManager.list_users())
        self.assertIsNotNone(self.userManager.add_user(userName=user, requirePasswordChange=True))
        self.assertIn("apiadmin",        str(self.userManager.list_users()))
        self.assertIn("apiadmin",        str(self.userManager.get_user(user)))
        self.assertEqual(True,           self.userManager.is_user(user))
        self.assertIn("devops",          str(self.userManager.get_user_roles(user)))
        self.assertIsNotNone(self.userManager.delete_user(user))
        self.assertNotIn("apiadmin",     self.userManager.list_users())
        self.assertEqual(False,          self.userManager.is_user(user))

        user = { "name" : "apimonitoring" , "role" : "apimonitoring"}
        self.userManager.delete_user(user)
        self.assertEqual(False,             self.userManager.is_user(user))
        self.assertNotIn("apimonitoring",   self.userManager.list_users())
        self.assertIsNotNone(self.userManager.add_user(userName=user))
        self.assertIn("apimonitoring",      str(self.userManager.list_users()))
        self.assertIn("apimonitoring",      str(self.userManager.get_user(user)))
        self.assertEqual(True,              self.userManager.is_user(user))
        self.assertIn("analytics",          str(self.userManager.get_user_roles(user)))
        self.assertIsNotNone(self.userManager.delete_user(user))
        self.assertNotIn("apimonitoring",   self.userManager.list_users())
        self.assertEqual(False,             self.userManager.is_user(user))

        user = { "name" : "AA" , "role" : "AA"}
        self.userManager.delete_user(user)
        self.assertEqual(False,             self.userManager.is_user(user))
        self.assertNotIn("AA",              self.userManager.list_users())
        self.assertIsNone(self.userManager.add_user(userName=user))
        self.assertEqual(False,             self.userManager.is_user(user))
        self.assertIn("WSO2_SERVER",        str(self.userManager.settings_get()))

        # Testing Commands
        prefix = "ws users "
        res = AepCtl.main(prefix + "help ")
        self.assertIn("create", res)
        res = AepCtl.main(prefix + "list help")
        self.assertIn("names", res)
        res = AepCtl.main(prefix + "delete apiconsumer")
        res = AepCtl.main(prefix + "get apiconsumer")
        self.assertNotIn("apiconsumer", res)
        res = AepCtl.main(prefix + "list users")
        self.assertNotIn("apiconsumer", res)
        res = AepCtl.main(prefix + "list ")
        self.assertNotIn("apiconsumer", res)
        res = AepCtl.main(prefix + "list names")
        self.assertNotIn("apiconsumer", res)
        res = AepCtl.main(prefix + "list roles")
        self.assertNotIn("apiconsumer", res)
        res = AepCtl.main(prefix + "create apiconsumer apiconsumer")
        self.assertIn("apiconsumer", res)
        res = AepCtl.main(prefix + "get apiconsumer")
        self.assertIn("apiconsumer", res)
        res = AepCtl.main(prefix + "list ")
        self.assertIn("apiconsumer", res)
        res = AepCtl.main(prefix + "delete apiconsumer")
        self.assertIn("apiconsumer", res)
        res = AepCtl.main(prefix + "get apiconsumer")
        self.assertNotIn("apiconsumer", res)
        res = AepCtl.main(prefix + "list ")
        self.assertNotIn("apiconsumer", res)

    def test_policy(self):  # Need WSO2 server to test this
        self.apiPolicyManager = Wso2PoliciesManager()
        self.apiPolicyManager.authentify()
        self.apiPolicyManager.policy_list(policyType="subscription")
        print(str(self.apiPolicyManager.d_data.get("count")))
        print(str(self.apiPolicyManager.d_data.get("list/0")))
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
        }
                """

        """
          "rateLimitCount": 5,
          "rateLimitTimeUnit": "sec",
          "subscriberCount": 10,
          "customAttributes": [],
          "stopOnQuotaReach": true,
          "billingPlan": "FREE"
        """
        # Delete leftover
        self.apiPolicyManager.delete(idName="TestPolicy2")
        new_pol = self.apiPolicyManager.create(entity=policy_create)
        if (not self.apiPolicyManager.isError()):
            policy_id = new_pol["policyId"]
            print(str(policy_id))
            del_pol = self.apiPolicyManager.delete(idName=policy_id)
        else:
            print(str("Creation Error"))

    def test_apis(self):  # Need WSO2 server to test this
        self.apiManager.authentify()
        self.apiManager.category_list()
        self.apiManager.api_list()
        apid = self.apiManager.api_id_by_name("3gpp-as-session-with-qos-4", "1.1.4")
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
        product_details = self.apiManager.product_details(product_id="fe9b9052-51b3-4491-91aa-eba355d7fc35")
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
        versions = self.apiManager.api_list(names_versions=True)
        print(str(versions))
        api_id = self.apiManager.api_id_by_name(name="3gpp-traffic-influence/1.1.2")
        self.devManager.unsubscribe(api_id=api_id, app_name="TestQosApp")
        self.devManager.subscribe(api_id=api_id, app_name="TestQosApp", policy="Unlimited")
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

    def test_Wso2Extract(self):
        wsp = Wso2Provisioning()
        wsp.extractWso2Apis()

    def test_prepareApisForFactoryData(self):
        wsp = Wso2Provisioning()
        wsp.prepareApisForFactoryData()

    def test_Wso2ProvisionCategory(self):
        wsp = Wso2Provisioning()
        wsp.provisionCategory("all")

    def test_LoadFactoryData(self):
        loader = FactoryLoader("file")
        data = loader.factory_loader(DATA_DIRECTORY+os.sep+"factory-dataset.json")
        logger.info(ut.to_json(data))

    def test_Wso2ProvisionAPI(self):
        wsp = Wso2Provisioning()
        api_store = StoreManager().getStore(name="APIs", store_type="file")
        apiList   = api_store.list(names=True)
        for apiName in apiList:
            wsp.provisionAPI(apiName)

    def test_all(self):
        self.test_userManager()
        self.test_policy()
        self.test_apis()
        self.test_products()
        self.test_settings()
        self.test_applications()
        self.test_subscriptions()
        self.test_dev_settings()
        pass


# Need DataStore Server to test this
class TestDataStore(unittest.TestCase):

    def setUp(self) -> None:
        global AEPCTL_Configuration
        AEPCTL_Configuration = ut.init_Configuration(cfg_filename=AEPCTL_Configuration_FileName,  # Default File Name
                                                     cmd_line_arg=CONFIG_FILE,  # Command Line Arg. FileName
                                                     env_cfg_var="AEPCTL_CONFIGURATION",  # Env Var with the FileName
                                                     default_cfg=def_AEPCTL_Configuration,  # Default Configuration
                                                     tag="AEPCTL Configuration")

        self.storeManager = StoreManager()
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def no_id(self, entry, id_att):
        if (isinstance(entry, ut.SuperDict)) :
            entry_no_id = copy.deepcopy(entry.getAsData())
            entry_no_id.pop(id_att, None)
            return entry_no_id
        if (isinstance(entry, dict)) :
            entry_no_id = copy.deepcopy(entry)
            entry_no_id.pop(id_att, None)
            return entry_no_id
        if (isinstance(entry, str)) :
            dentry = ut.loadDataContent(entry)
            entry_no_id = copy.deepcopy(dentry)
            entry_no_id.pop(id_att, None)
            return ut.to_json(entry_no_id)

    def generic_test(self, store : str , new_entry : str, store_type="file", backup : bool=False):  # Need DataStore server to test this
        store_entity = store
        store    = self.storeManager.getStore(store, file=store_type)
        id_att   = self.storeManager.get_id_att(store.entity_type)
        name_att = self.storeManager.get_name_att(store.entity_type)
        desc_att = self.storeManager.get_desc_att(store.entity_type)
        new_entry_dict = ut.loadDataContent(new_entry)
        # Backup Entries
        # backup_entries_list = store.list()
        backup_entries = store.deleteAll(backup=backup)
        # self.assertEqual(backup_entries_list, backup_entries)  # too long sometimes

        # Now should be empty
        self.assertEqual([], store.list())
        self.assertEqual(0,  store.list(count=True))
        self.assertEqual([], store.list(names=True))
        self.assertEqual([], store.list(ids=True))

        # Create Entry Errors
        entry = store.create(entity="TT", backup=backup)
        self.assertEqual(None, entry)
        self.assertEqual(True, store.isError())
        self.assertIn("Invalid JSON or YAML Format : TT", store.getError())
        entry = store.create(entity=5, backup=backup)
        self.assertEqual(None, entry)
        self.assertEqual(True, store.isError())
        self.assertIn("Invalid Dict Format : 5", store.getError())

        # Create Entry
        entry = store.create(entity=new_entry, backup=backup)
        print(str(new_entry))
        print(str(store.getError()))
        self.assertEqual(False, store.isError())
        self.assertEqual(1, store.list(count=True))
        self.assertEqual(entry[name_att], new_entry_dict[name_att])
        self.assertEqual(entry[desc_att], new_entry_dict[desc_att])
        print(ut.to_json(entry))
        print(ut.to_json(entry[id_att]))
        print(ut.to_json(entry[name_att]))
        print(ut.to_json(entry[desc_att]))
        self.assertEqual(new_entry_dict, self.no_id(store.get(idName=entry[id_att]),     id_att))
        self.assertEqual(new_entry_dict, self.no_id(store.get(identifier=entry[id_att]), id_att))
        self.assertEqual(new_entry_dict, self.no_id(store.get(idName=entry[name_att]),   id_att))
        self.assertEqual(new_entry_dict, self.no_id(store.get(name=entry[name_att]),     id_att))

        self.assertEqual(1,  store.list(count=True))
        self.assertEqual([entry[name_att]], store.list(names=True))
        self.assertEqual([entry[id_att]], store.list(ids=True))

        # No Entries
        none_entry = store.get(name="TT")
        self.assertEqual(none_entry, None)
        self.assertEqual(True, store.isError())
        self.assertEqual("No such entry : TT", store.getError())

        none_entry = store.get(identifier="IDTT")
        self.assertEqual(none_entry, None)
        self.assertEqual(True, store.isError())
        self.assertIn("No", store.getError())

        # Test Exist
        self.assertEqual(False, store.exist(idName="IDTT"))
        self.assertEqual(True,  store.exist(idName=entry[id_att]))

        # Test Get By
        self.assertEqual(entry[id_att], store.idByName(idName=entry[id_att]))
        self.assertEqual(entry[name_att], store.nameById(idName=entry[id_att]))
        self.assertEqual(entry[desc_att], store.descByIdname(idName=entry[id_att]))
        self.assertEqual(entry[id_att], store.idByName(idName=entry[name_att]))
        self.assertEqual(entry[name_att], store.nameById(idName=entry[name_att]))
        self.assertEqual(entry[desc_att], store.descByIdname(idName=entry[name_att]))
        self.assertEqual(None, store.idByName(idName="TT"))
        self.assertEqual(None, store.nameById(idName="TT"))
        self.assertEqual(None, store.descByIdname(idName="TT"))

        # Get Entry Errors
        none_entry = store.get(idName="TT")
        self.assertEqual(none_entry, None)
        self.assertEqual(True, store.isError())
        self.assertEqual("No such entry : TT", store.getError())

        # Create Entry Errors
        created_entry = store.create(entity="TT", backup=backup)
        self.assertEqual(None, created_entry)
        self.assertEqual(True, store.isError())
        self.assertEqual("Invalid JSON or YAML Format : TT", store.getError())
        created_entry = store.create(entity=5, backup=backup)
        self.assertEqual(None, created_entry)
        self.assertEqual(True, store.isError())
        self.assertEqual("Invalid Dict Format : 5", store.getError())
        create_entry = copy.deepcopy(ut.loadDataContent(new_entry))
        create_entry.pop(name_att, None)
        created_entry = store.create(entity=create_entry, backup=backup)
        self.assertEqual(None, created_entry)
        self.assertEqual(True, store.isError())
        self.assertIn("'"+name_att+"' is a required property", store.getError())

        # Update Entry
        update_entry = copy.deepcopy(store.get(idName=entry[id_att]))
        update_entry[desc_att] = "New Description"
        new_entry = store.update(update_entry, backup=backup)
        self.assertEqual(new_entry[desc_att], "New Description")
        new_entry = store.get(idName=entry[id_att])
        self.assertEqual(new_entry, store.get(idName=entry[id_att]))

        # Update Entry Errors
        update_entry = copy.deepcopy(store.get(idName=entry[id_att]))
        update_entry.pop(name_att, None)
        updated_entry = store.update(entity=update_entry, backup=backup)
        self.assertEqual(None, updated_entry)
        self.assertEqual(True, store.isError())
        self.assertIn("'"+name_att+"' is a required property", store.getError())
        update_entry = store.update(entity="TT", backup=backup)
        self.assertEqual(None, update_entry)
        self.assertEqual(True, store.isError())
        self.assertEqual("Invalid JSON or YAML Format : TT", store.getError())
        update_entry = store.update(entity=5, backup=backup)
        self.assertEqual(None, update_entry)
        self.assertEqual(True, store.isError())
        self.assertEqual("Invalid Dict Format : 5", store.getError())

        # Delete Entry Errors
        deleted_entry = store.delete(identifier="TT", backup=backup)
        self.assertEqual(None, deleted_entry)
        self.assertEqual(True, store.isError())
        self.assertEqual("No such entry : TT", store.getError())
        deleted_entry = store.delete(idName="TT", backup=backup)
        self.assertEqual(None, deleted_entry)
        self.assertEqual(True, store.isError())
        self.assertEqual("No such entry : TT", store.getError())
        deleted_entry = store.delete(name="TT", backup=backup)
        self.assertEqual(None, deleted_entry)
        self.assertEqual(True, store.isError())
        self.assertEqual("No such entry : TT", store.getError())

        # Delete Entry Errors
        to_delete = store.get(idName=entry[id_att])
        deleted_entry = store.delete(identifier=entry[id_att], backup=backup)
        self.assertEqual(to_delete, deleted_entry)
        self.assertEqual(False, store.isError())
        self.assertEqual(0, store.list(count=True))

        # Delete All Entries
        entry = store.create(entity=new_entry, backup=backup)
        self.assertIsNotNone(entry)
        self.assertEqual(1, store.list(count=True))
        store.deleteAll(backup=backup)
        self.assertEqual(0, store.list(count=True))

        openapi = StoreManager().get_openapi(entity=store_entity)
        self.assertIsNotNone(openapi)
        schema  = StoreManager().get_schema(entity=store_entity)
        self.assertIsNotNone(schema)

        # Restore Entries
        for entry in backup_entries :
            store.create(entry, backup=backup)
        entry_list = store.list()
        self.assertIsNotNone(entry_list)
        # It differs because of create which creates new ids. ... to be fixed.
        # self.assertEqual(backup_entries_list, entry_list)

    def generic_commands(self, store : str , new_entry : str, store_type="file", backup : bool=False):  # Need DataStore server to test this
        store    = self.storeManager.getStore(store, file=store_type)
        id_att   = self.storeManager.get_id_att(store.entity_type)
        name_att = self.storeManager.get_name_att(store.entity_type)
        desc_att = self.storeManager.get_desc_att(store.entity_type)

        # Backup Entries
        backup_entries_list = store.list()
        backup_entries      = store.deleteAll(backup=backup)
        self.assertEqual(backup_entries_list, backup_entries)

        entry_file_name = ".payload.json"
        entry = ut.loadDataContent(new_entry)
        entry[id_att] = "id"
        ut.saveJsonFile(entry, entry_file_name)

        verbose  = "-v"
        service  = "fs " if (store_type.lower() == "file") else "ds "
        ent_type = store.entity_type
        prefix = verbose + " " + service + " " + ent_type + " "

        # Delete All
        res = AepCtl.main(prefix + "delete all")
        self.assertIn("[", res)
        res = AepCtl.main(prefix + "list count")
        self.assertIn("0", res)

        # Now should be empty
        res = AepCtl.main(prefix + "list")
        self.assertEqual(res, "[]")
        res = AepCtl.main(prefix + "list ids")
        self.assertEqual(res, "[]")
        res = AepCtl.main(prefix + "list names")
        self.assertEqual(res, "[]")
        res = AepCtl.main(prefix + "list count")
        self.assertEqual(res, "0")

        # Create Entry
        res = AepCtl.main(prefix + "create " + entry_file_name)
        self.assertIn(entry[desc_att], res)
        created_entry = ut.loadDataContent(res)
        res = AepCtl.main(prefix + "list names")
        self.assertIn(entry[name_att], res)
        res = AepCtl.main(prefix + "list ids")
        self.assertIn(created_entry[id_att], res)
        res = AepCtl.main(prefix + "list count")
        self.assertIn("1", res)
        res = AepCtl.main(prefix + "list")
        self.assertIn(entry[name_att], res)
        self.assertIn(created_entry[id_att], res)
        self.assertIn(entry[desc_att], res)

        # Create Entry Errors
        entry_error_file_name = ".payload_error.json"
        ut.saveFileContent("TT", entry_error_file_name)
        res = AepCtl.main(prefix + "create -p " + entry_error_file_name)
        self.assertIn("Cannot JSON/YAML Decode", res)
        ut.saveFileContent("5", entry_error_file_name)
        res = AepCtl.main(prefix + "create -p " + entry_error_file_name)
        self.assertIn("Cannot JSON/YAML Decode", res)

        # Get Testing
        res = AepCtl.main(prefix + "get " + created_entry[id_att])  # by ID
        self.assertIn(entry[name_att], res)
        self.assertIn(created_entry[id_att], res)
        self.assertIn(entry[desc_att], res)
        self.assertEqual(self.no_id(entry, id_att), ut.loadDataContent(self.no_id(res, id_att)))
        res = AepCtl.main(prefix + "get " + created_entry[name_att])  # by Name
        self.assertIn(entry[name_att], res)
        self.assertIn(created_entry[id_att], res)
        self.assertIn(entry[desc_att], res)
        self.assertEqual(self.no_id(entry, id_att), ut.loadDataContent(self.no_id(res, id_att)))

        # Get Entry Errors
        res = AepCtl.main(prefix + "get TT")
        self.assertIn("No such entry : TT", res)

        # Update Entry
        entry_file_name = ".payload.json"
        res = AepCtl.main(prefix + "get " + created_entry[id_att])  # by ID
        entry = ut.loadDataContent(res)
        entry[desc_att] = "New Description"
        ut.saveJsonFile(entry, entry_file_name)

        res = AepCtl.main(prefix + "update -p " + entry_file_name)
        self.assertIn("New Description", res)
        res = AepCtl.main(prefix + "get " + created_entry[id_att])  # by ID
        self.assertIn("New Description", res)

        # Update Entry Errors
        ut.saveFileContent("TT", entry_error_file_name)
        res = AepCtl.main(prefix + "update -p " + entry_error_file_name)
        self.assertIn("Cannot JSON/YAML Decode", res)
        ut.saveFileContent("5", entry_error_file_name)
        res = AepCtl.main(prefix + "update -p " + entry_error_file_name)
        self.assertIn("Cannot JSON/YAML Decode", res)

        update_entry = ut.loadDataFile(entry_file_name)
        update_entry.pop(name_att, None)
        update_entry = ut.saveDataFile(update_entry, entry_file_name)
        res = AepCtl.main(prefix + "update -p " + entry_file_name)
        self.assertIn("is a required property", res)

        # Delete Entry Errors
        res = AepCtl.main(prefix + "delete TT ")
        self.assertIn("No such entry : TT", res)

        # Delete Entry
        res = AepCtl.main(prefix + "delete " + created_entry[id_att])  # by ID
        self.assertIn("New Description", res)
        res = AepCtl.main(prefix + "get " + created_entry[id_att])  # by ID
        self.assertIn("No such entry", res)

        # openapi / schema
        res = AepCtl.main(prefix + "openapi ")
        self.assertIn("components", res)
        res = AepCtl.main(prefix + "get openapi ")
        self.assertIn("components", res)
        res = AepCtl.main(prefix + "schema ")
        self.assertIn("$schema", res)
        res = AepCtl.main(prefix + "get schema ")
        self.assertIn("$schema", res)

        # help
        res = AepCtl.main(prefix + "help ")
        self.assertIn("[help|get", res)
        res = AepCtl.main(prefix + " help get")
        self.assertIn("[help|get", res)
        res = AepCtl.main("help ")
        self.assertIn("providers", res)
        res = AepCtl.main("")
        self.assertIn("No command nor resource specified", res)

        # Reset Store
        res = AepCtl.main(prefix + "delete all")
        self.assertIn("[", res)
        res = AepCtl.main(prefix + "list count")
        self.assertIn("0", res)
        res = AepCtl.main(prefix + " list")
        self.assertEqual(res, "[]")
        res = AepCtl.main(prefix + " list ids")
        self.assertEqual(res, "[]")
        res = AepCtl.main(prefix + " list names")
        self.assertEqual(res, "[]")

        # Restore Entries
        for entry in backup_entries :
            store.create(entry, backup=backup)
        entry_list = store.list()
        # It differs because of create which creates new ids. ... to be fixed.
        # self.assertEqual(backup_entries_list, entry_list)

        return

    def test_Categories(self, store_type="file", backup : bool = False):  # Need DataStore server to test this
        new_entry = """
        {
            "CategoryName": "Finance",
            "CategoryLogo": "CategoryLogo",
            "CategoryDescription": "Finance related APIs"
        }  
        """
        self.generic_test("Categories", new_entry, store_type=store_type, backup=backup)
        self.generic_commands("Categories", new_entry, store_type=store_type, backup=backup)

    def test_Articles(self, store_type="file", backup : bool=False):
        new_entry = """
        { 
          "ArticleName" : "ArticleName",
          "ArticleDescription": "ArticleDescription",
          "ArticlePage": "ArticlePage",
          "ArticleLogo": "ArticleLogo"
          }
        """
        self.generic_test("Articles", new_entry, store_type=store_type, backup=backup)
        self.generic_commands("Articles", new_entry, store_type=store_type, backup=backup)

    def test_ProvidersRest(self):
        self.test_Providers(store_type="rest", backup=False)

    def test_Providers(self, store_type="file", backup : bool = False):
        new_entry = """
        { 
          "ProviderName" : "ProviderName",
          "ProviderDescription": "ProviderDescription",
          "Contact": "Contact",
          "WebSite": "WebSite",
          "ProviderIcon": "ProviderIcon",
          "ProviderBigLogo": "ProviderBigLogo"
          }
        """
        self.generic_test("Providers", new_entry, store_type=store_type, backup=backup)
        self.generic_commands("Providers", new_entry, store_type=store_type, backup=backup)

    def test_Accounts(self, store_type="file", backup : bool = False):
        new_entry = """
        { 
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
        self.generic_test("Accounts", new_entry, store_type=store_type, backup=backup)
        self.generic_commands("Accounts", new_entry, store_type=store_type, backup=backup)

    def test_loader(self):
        loader = FactoryLoader("file")
        data = loader.factory_loader(DATA_DIRECTORY+os.sep+"factory-dataset.json")
        logger.info(ut.to_json(data))

    def test_dumper(self):
        StoreManager.store_back_up()

    def test_all_entities(self, store_type="file", backup : bool=False):
        self.test_Providers(store_type=store_type, backup=backup)
        # self.test_Categories(store_type=store_type, backup=backup)
        self.test_Articles(store_type=store_type, backup=backup)
        # self.test_Accounts(store_type=store_type, backup=backup) # Schema Errors (missing referenced schema)

    def test_all(self, store_type="file"):
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.test_all_entities(store_type=store_type, backup=False)

    def test_all_rest(self):
        self.test_all(store_type="rest")

    def test_all_anme(self):
        self.test_all(store_type="anme")

    def test_all_file(self):
        self.test_all(store_type="file")

    def test_ANME(self):
        new_entry = """
        { 
          "ArticleName" : "ArticleName",
          "ArticleDescription": "ArticleDescription",
          "ArticlePage": "ArticlePage",
          "ArticleLogo": "ArticleLogo"
          }
        """
        # server = AEPCTL_Configuration.get("ANME_SERVER")
        # server = "https://localhost:5000"
        server = "https://anme.pagekite.me"
        anme = AnmeDataStore(server=server, entity_type="articles")
        theList = anme.list(ids=True)
        print(theList)
        entry = anme.create(new_entry)
        print(entry)
        theList = anme.list()
        print(theList)


class TestAll(unittest.TestCase):

    def test_all(self):
        # DataStore
        tds = TestDataStore()
        tds.setUp()
        # tds.test_all_file()
        # tds.test_all_rest()
        tds.test_all_anme()
        # WS02
        # tws = TestWso2Manager()
        # tws.setUp()
        # tws.test_all()
