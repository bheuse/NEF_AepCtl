#! /usr/bin/python3

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
from rich.console import Console
from rich.markdown import Markdown
import Util as ut
import Util_GUI as utg
from prompt_toolkit import PromptSession
from prompt_toolkit import HTML
from prompt_toolkit.history import FileHistory
from prompt_toolkit.completion import NestedCompleter
from prompt_toolkit.completion import PathCompleter
from prompt_toolkit.contrib.completers.system import SystemCompleter
import aepctlui

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
logger = logging.getLogger(__name__)

###
### Globals
###

# HOME : Where the configuration is stored
# WORK : Where the runtime data  is stored
# ROOT : Where the applications and static data are installed

AEPCTL_HOME_DIR      = os.path.expanduser('~') + os.sep + ".aepctl"  # HOME Directory
AEPCTL_WORK_DIR      = os.getcwd()                                   # First Time Set Up
AEPCTL_ROOT_DIR      = os.getcwd()                                   # First Time Set Up
AEPCTL_DIRECTORY     = AEPCTL_ROOT_DIR                               # First Time Set Up

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


def set_aepctl_dirs(P_AEPCTL_ROOT_DIR : str, P_AEPCTL_WORK_DIR : str):
    global CONFIG_DIRECTORY, TMP_DIRECTORY, DATA_DIRECTORY, TEST_DIRECTORY
    global LOGS_DIRECTORY, SCRIPTS_DIRECTORY, BACKUP_DIRECTORY, STORE_DIRECTORY
    global STORES_FILE, CONFIG_FILE
    CONFIG_DIRECTORY   = P_AEPCTL_ROOT_DIR + os.sep + "etc"
    DATA_DIRECTORY     = P_AEPCTL_ROOT_DIR + os.sep + "data"
    TMP_DIRECTORY      = P_AEPCTL_ROOT_DIR + os.sep + "tmp"
    TEST_DIRECTORY     = P_AEPCTL_ROOT_DIR + os.sep + "tests"
    LOGS_DIRECTORY     = P_AEPCTL_ROOT_DIR + os.sep + "logs"
    SCRIPTS_DIRECTORY  = P_AEPCTL_ROOT_DIR + os.sep + "scripts"
    BACKUP_DIRECTORY   = P_AEPCTL_ROOT_DIR + os.sep + "backup"
    STORE_DIRECTORY    = P_AEPCTL_WORK_DIR + os.sep + "store"
    STORES_FILE        = P_AEPCTL_ROOT_DIR + os.sep + "etc" + os.sep + "stores.json"

WSO2_SERVER     = "https://localhost:9443"
CATALOG_SERVER  = "http://localhost:30106"
USERS_SERVER    = "http://localhost:30107"

###
### Configuration
###

def_AEPCTL_Configuration = ut.SuperDict(name="AEPCTL_DefaultConfiguration", data=
{
    "Description"                  : "Default AEPCTL Configuration",
    "WSO2_SERVER"                  : WSO2_SERVER,
    "CATALOG_SERVER"               : CATALOG_SERVER,
    "USERS_SERVER"                 : USERS_SERVER,
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

    def __init__(self, server=WSO2_SERVER, service : str = "admin"):
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

    def hasData(self, code=[200, 202, 204]):
        if (self.r_code in code) and (self.d_data) :
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
            return AEPCTL_Configuration.get("USERS_SERVER") + "/nef-application-user-profile-service/22-03/" + "datastore" + "/" + re.sub("^/", "", endpoint) + ("/" + entry if (entry) else "")
        if (service == "datastore") or (service == "catalog"):
            return AEPCTL_Configuration.get("CATALOG_SERVER") + "/nef-services-catalog-service/22-03/" + "datastore" + "/" + re.sub("^/", "", endpoint) + ("/" + entry if (entry) else "")
        if (service == "subscription"):
            return self.server + "/nef-api-subsciption-service/22-03/" + re.sub("^/", "", endpoint) + ("/" + entry if (entry) else "")
        return self.server + "/api/am/"+service+"/v2/" + re.sub("^/", "", endpoint) + ("/" + entry if (entry) else "")

    def authentify(self):
        if (self.authentified) : return
        if (self.service != "admin") :
            self.authentified = True  # No auth on DataStores for now
            return

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
            if (isinstance(payload, ut.SuperDict)): self.s_data = payload.clean().getAsData()
            if (isinstance(payload, str)):          self.s_text = payload
        if (self.s_data):
            self.s_text = json.dumps(self.s_data)
        payload = None
        if (payload):
            if (isinstance(payload, dict)):         payload  = json.dumps(payload)
            if (isinstance(payload, ut.SuperDict)): payload  = json.dumps(payload.clean().getAsData())
            if (isinstance(payload, str)):          payload  = ut.loadDataContent(payload)
            payload    = ut.to_json(payload)
        # print(str(payload))
        # print(str(jsonObject))
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

    def __init__(self, entity_type="articles", name_att="ArticleName", desc_att="ArticleDesc", id_att="id", service="datastore"):
        self.errortxt    = None
        self.entity_type = entity_type
        self.name_att    = name_att
        self.desc_att    = desc_att
        self.id_att      = id_att
        self.service     = service
        self.cache       = None

    def error(self, error_text : Union [str, None] = "") -> Union [str, None]:
        if (error_text == ""): return self.errortxt
        if (not error_text): self.errortxt = None
        if (error_text) : logger.error(error_text)
        self.errortxt = error_text
        return self.errortxt

    def isError(self) -> bool:
        return (self.error() != None)

    def resetError(self):
        self.error(None)

    def setError(self, error_text : str):
        self.error(error_text)

    def getError(self) -> str:
        return self.error()

    def create(self, entity : Union[str, dict], backup : bool = True) -> Union [dict, None]:
        self.resetError()
        p_entity = entity
        if (isinstance(entity, str)) :
            entity = ut.loadDataContent(entity)
            if (not entity):
                self.setError("Invalid JSON or YAML Format : "+str(p_entity))
                return None
        if (not isinstance(entity, dict)) :
            self.setError("Invalid Format : "+str(p_entity))
            return None
        entity[self.id_att] = ut.uuid()
        self.setError(StoreManager.check_schema(entity, self.entity_type))
        if (self.error()):
            return None
        if (backup):
            StoreManager.store_back_up(service="file")
        return entity

    def list(self, names : bool = False, ids : bool = False, count : bool = False) -> Union [list, None, int]:
        pass   # pragma: no cover

    def id_by_name(self, idName : str) -> str:
        pass   # pragma: no cover

    def name_by_id(self, idName : str) -> str:
        pass   # pragma: no cover

    def desc_by_idname(self, idName : str) -> Union[str, None]:
        pass   # pragma: no cover

    def exist(self, idName : str) -> bool:
        pass   # pragma: no cover

    def get(self, idName : str = None , name : str = None, identifier : str = None) -> Union [dict, None, str]:
        self.resetError()
        entity_id = None
        value = None
        if (idName):
            value = idName
            entity_id = self.id_by_name(idName)
        if (name):
            value = name
            entity_id = self.id_by_name(name)
        if (identifier):
            value = identifier
            entity_id = identifier
        if (not entity_id):
            self.setError("No such entry : " + str(value))
        return entity_id

    def update(self, entity : Union[str, dict], backup : bool = True) -> Union [dict, None]:
        self.resetError()
        p_entity = entity
        if (isinstance(entity, str)) :
            entity = ut.loadDataContent(entity)
            if (not entity):
                self.setError("Invalid JSON or YAML Format : "+str(p_entity))
                return None
        if (not isinstance(entity, dict)) :
            self.setError("Invalid Format : "+str(p_entity))
            return None
        self.setError(StoreManager.check_schema(entity, self.entity_type))
        if (self.error()):
            return None
        if (backup):
            StoreManager.store_back_up(service=self.service)

    def delete(self, idName : str = None , name : str = None, identifier : str = None, backup : bool = True) -> Union [dict, None]:
        self.resetError()
        entity_id = None
        value = None
        if (idName):
            value = idName
            entity_id = self.id_by_name(idName)
        if (name):
            value = name
            entity_id = self.id_by_name(name)
        if (identifier):
            value = identifier
            entity_id = identifier
        entry = self.get(idName=entity_id)
        if (not entry) :
            self.setError("No such entry : " + str(value))
            return None
        if (backup):
            StoreManager.store_back_up(service="file")
        return entry

    def delete_all(self, backup : bool = True) -> Union [list, None]:
        pass   # pragma: no cover

    def dump_all(self, filename : str = None, directory : str = BACKUP_DIRECTORY) -> dict:
        self.resetError()
        entries = self.list()
        store = dict()
        store["desc_att"]  = self.desc_att
        store["name_att"]  = self.name_att
        store["service"]   = self.service
        store["entity"]    = self.entity_type
        store["count"]     = len(entries) if (entries) else 0
        store["timestamp"] = ut.timestamp()
        store["entries"]   = entries if (entries) else []
        if (not ut.safeDirExist(directory)):
            logger.info("Creating Directory : " + directory)
            ut.safeCreateDir(directory)
        if (not filename):
            ut.safeCreateDir(directory)
            logger.info("BackUp Dir : " + directory)
            filename = directory + os.sep + self.entity_type + "_dump.json"
        ut.saveJsonFile(store, filename)
        logger.info(str(self.service)+" [" + self.entity_type + "] Store saved in file : " + filename)
        return store

    def backup(self, filename : str = None, directory : str = BACKUP_DIRECTORY) -> dict:
        return self.dump_all(filename, directory)

    def store_file(self, filename : str = None, directory : str = None) -> dict:
        global STORE_DIRECTORY
        if (not directory) : directory = STORE_DIRECTORY
        return self.dump_all(filename, directory)

    def load_file(self, filename : str = None, directory : str = None) -> list:
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
            self.store_file()                                 # pragma: no cover
        logger.info("Loading File       : " + filename)
        data = ut.loadDataFile(filename)
        if (not data):
            logger.info("Invalid Data Format : " + filename)  # pragma: no cover
            return None                                       # pragma: no cover
        data = StoreManager.check_entry(data)
        if (not data):
            logger.info("Invalid Data Format : " + filename)  # pragma: no cover
            return None                                       # pragma: no cover
        self.entity_type = data["entity"]
        self.name_att    = data["name_att"]
        self.desc_att    = data["desc_att"]
        self.service     = data["service"]
        self.cache       = data["entries"]
        self.cache       = sorted(self.cache, key=lambda d: d[self.name_att])
        logger.info("Loaded File  : " + filename)
        return self.cache


class FileDataStore(DataStoreInterface):

    def __init__(self, directory=None, entity_type="articles", name_att="ArticleName", desc_att="ArticleDesc", id_att="id", service="datastore"):
        global STORE_DIRECTORY
        if (not directory) : directory = STORE_DIRECTORY
        DataStoreInterface.__init__(self, entity_type=entity_type, name_att=name_att, desc_att=desc_att, id_att=id_att, service=service)
        self.cache       = self.load_file(directory=directory)

    def create(self, entity : Union[str, dict], backup : bool = True) -> Union [dict, None]:
        entry = super(FileDataStore, self).create(entity=entity, backup=backup)
        if (self.isError()): return None
        if (not entry): return None
        self.cache.append(entry)
        self.cache = sorted(self.cache, key=lambda d: d[self.name_att])
        self.store_file()
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
        if (entries == None):
            return list()
        self.cache = sorted(entries, key=lambda d: d[self.name_att])
        return entries

    def id_by_name(self, idName : str) -> Union[str, None]:
        entries = self.cache
        for entry in entries:
            if (entry[self.name_att] == idName): return entry[self.id_att]
            if ((self.id_att in entry) and entry[self.id_att] == idName):   return entry[self.id_att]
        return None

    def name_by_id(self, idName : str) -> Union[None, str]:
        entries = self.cache
        for entry in entries:
            if ((self.id_att in entry) and entry[self.id_att] == idName):  return entry[self.name_att]
            if (entry[self.name_att] == idName): return entry[self.name_att]
        return None

    def desc_by_idname(self, idName : str) -> Union[str, None]:
        entries = self.cache
        for entry in entries:
            if ((self.id_att in entry) and entry[self.id_att] == idName):  return entry[self.desc_att]
            if (entry[self.name_att] == idName): return entry[self.desc_att]
        return None

    def exist(self, idName : str) -> bool:
        self.resetError()
        entries = self.cache
        for entry in entries:
            if (entry[self.name_att] == idName): return True
            if ((self.id_att in entry) and (entry[self.id_att]   == idName)): return True
        return False

    def get(self, idName : str = None , name : str = None, identifier : str = None) -> Union [dict, None, str]:
        entity_id = super(FileDataStore, self).get(idName=idName, name=name, identifier=identifier)
        if (not entity_id): return None
        for entry in self.cache:
            if ((self.id_att in entry) and entry[self.id_att] == str(entity_id)): return entry
        self.setError("No such entry : " + str(entity_id))
        return None

    def update(self, entity : Union[str, dict], backup : bool = True) -> Union [dict, None]:
        super(FileDataStore, self).update(entity=entity, backup=backup)
        if (self.isError()): return None
        new_entity = entity
        if (self.id_att in entity):
            entity_id  = entity[self.id_att]
            old_entity = self.delete(identifier=entity_id)
            if (old_entity): new_entity = old_entity | entity
        self.cache.append(new_entity)
        self.cache = sorted(self.cache, key=lambda d: d[self.name_att])
        self.store_file()
        return new_entity

    def delete(self, idName : str = None , name : str = None, identifier : str = None, backup : bool = True) -> Union [dict, None]:
        entry = super(FileDataStore, self).delete(idName=idName, name=name, identifier=identifier, backup=backup)
        if (self.isError()): return None
        if (not entry): return None
        if (self.id_att not in entry): return None
        filtered_list = [d for d in self.cache if d[self.id_att] != entry[self.id_att]]
        self.cache = filtered_list
        self.cache = sorted(self.cache, key=lambda d: d[self.name_att])
        self.store_file()
        return entry

    def delete_all(self, backup : bool = True) -> Union [list, None]:
        self.resetError()
        if (backup):
            StoreManager.store_back_up(service="file")
        deleted = copy.deepcopy(self.cache)
        self.cache.clear()
        self.store_file()
        return deleted

    def load_file(self, filename : str = None, directory : str = None) -> list:
        global STORE_DIRECTORY
        if (not directory) : directory = STORE_DIRECTORY
        entry_list = super(FileDataStore, self).load_file(filename=filename, directory=directory)
        return entry_list

    def copy_ds_to_fs(self, reset=False) -> dict:
        self.resetError()
        server = RestDataStore(entity_type=self.entity_type, name_att=self.name_att, desc_att=self.desc_att, id_att=self.id_att, service=self.service)
        if (reset) :
            self.delete_all(backup=True)
        for entry in server.list():
            self.update(entry)
        self.cache = sorted(self.cache, key=lambda d: d[self.name_att])
        return self.cache

    def copy_fs_to_ds(self, reset=False) -> dict:
        self.resetError()
        server = RestDataStore(entity_type=self.entity_type, name_att=self.name_att, desc_att=self.desc_att, id_att=self.id_att, service=self.service)
        if (reset) :
            server.delete_all(backup=True)
        for entry in self.cache:
            server.update(entry)
        return server.list()


class RestDataStore(DataStoreInterface, RestHandler):

    def __init__(self, server=CATALOG_SERVER, entity_type="articles", name_att="ArticleName", desc_att="ArticleDesc", id_att="id", service="datastore"):
        DataStoreInterface.__init__(self, entity_type=entity_type, name_att=name_att, desc_att=desc_att, id_att=id_att, service=service)
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

    def list(self, names : bool = False, ids : bool = False, count : bool = False) -> Union [list, None]:
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

    def id_by_name(self, idName : str) -> Union[str, None]:
        self.resetError()
        self.handle_request("LIST", self.entity_type, service=self.service)
        if (not self.hasData()) :
            self.setError("LIST ["+self.entity_type+"] : No Data from Server\n"+str(self._getError()))
            return None
        entry_list = sorted(self.d_data.getAsData()["list"], key=lambda d: d[self.name_att])
        for cat in entry_list :
            if (cat[self.name_att] == idName): return cat[self.id_att]
            if (cat[self.id_att] == idName):   return cat[self.id_att]
        return None

    def name_by_id(self, idName : str) -> Union[str, None]:
        self.resetError()
        self.handle_request("LIST", self.entity_type, service=self.service)
        if (not self.hasData()) :
            self.setError("LIST ["+self.entity_type+"] : No Data from Server\n"+str(self._getError()))
            return None
        entry_list = sorted(self.d_data.getAsData()["list"], key=lambda d: d[self.name_att])
        for cat in entry_list :
            if (cat[self.id_att] == idName):   return cat[self.name_att]
            if (cat[self.name_att] == idName): return cat[self.name_att]
        return None

    def desc_by_idname(self, idName : str) -> Union[str, None]:
        self.resetError()
        self.handle_request("LIST", self.entity_type, service=self.service)
        if (not self.hasData()) :
            self.setError("LIST ["+self.entity_type+"] : No Data from Server\n"+str(self._getError()))
            return None
        entry_list = sorted(self.d_data.getAsData()["list"], key=lambda d: d[self.name_att])
        for cat in entry_list :
            if (cat[self.id_att] == idName):   return cat[self.desc_att]
            if (cat[self.name_att] == idName): return cat[self.desc_att]
        return None

    def exist(self, idName : str) -> bool:
        self.resetError()
        self.handle_request("LIST", self.entity_type, service=self.service)
        if (not self.hasData()) :
            self.setError("LIST ["+self.entity_type+"] : No Data from Server\n"+str(self._getError()))
            return None
        entry_list = sorted(self.d_data.getAsData()["list"], key=lambda d: d[self.name_att])
        for cat in entry_list :
            if (cat[self.name_att] == idName): return True
            if (cat[self.id_att] == idName):   return True
        return False

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

    def delete_all(self, backup : bool = True) -> Union [list, None]:
        self.resetError()
        all_errors = ""
        entries    = list()
        if (backup):
            StoreManager.store_back_up(service="rest")
        for entry_id in self.list(ids=True) :
            entry = self.delete(idName=entry_id, backup=False)
            if (entry): entries.append(entry)
            if (self.isError()):
                all_errors = all_errors + "\n" + self.getError()
        if (all_errors != "") :
            self.setError(all_errors)
        logger.info("Rest Store Deleted all : ["+self.entity_type+"]")
        return entries

    def load_file(self, filename : str = None, directory : str = None) -> dict:
        global STORE_DIRECTORY
        if (not directory) : directory = STORE_DIRECTORY
        entry_list = super(DataStoreInterface, self).load_file(filename=filename, directory=directory)
        for entry in entry_list :
            self.update(entry)
        logger.info("Loaded File  : " + filename)
        return self.cache

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
# apiCreatorRoles  = [ 'Internal/everyone', 'Internal/creator',   'Application/rest_api_publisher', 'Application/apim_publisher', 'Internal/publisher',]
apiCreatorRoles  = [ 'Internal/everyone', 'Internal/creator',  'Application/apim_publisher', 'Internal/publisher']
apiConsumerRoles = [ 'Internal/everyone', 'Application/apim_devportal' ]
apiAdminRoles    = [ 'Internal/everyone', 'admin', 'Internal/devops', 'Internal/analytics' ]
apiMonitoring    = [ 'Internal/everyone', 'Internal/analytics']


def wso2_browser(what : str = "publisher", w_server : str = None):
    if (not w_server):
        w_server = AEPCTL_Configuration.get("WSO2_SERVER")
    if (what.lower() in ["publisher", "apim"]):
        ut.open_browser(w_server + "/publisher")
        return "API Publisher Portal : " + w_server + "/publisher"
    if (what.lower() in ["devportal", "dev", "portal"]):
        ut.open_browser(w_server + "/devportal")
        return "WSO2 API Developer Portal : " + w_server + "/devportal"
    if (what.lower() in ["mgt", "console", "carbon"]):
        ut.open_browser(w_server + "/carbon/")
        return "WSO2 Mgt Console Portal : " + w_server + "/carbon/"
    return


class Wso2UsersManager(DataStoreInterface):

    def __init__(self, authorization="YWRtaW46YWRtaW4=", server=WSO2_SERVER, entity_type="users", name_att="name", desc_att="role", id_att="name", service="ws02store"):
        DataStoreInterface.__init__(self, entity_type=entity_type, name_att=name_att, desc_att=desc_att, id_att=id_att, service=service)
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

    def settings_get(self) -> dict:
        settings = ut.SuperDict(name="ADMIN SETTINGS")
        settings["authorization"] = self.authorization
        settings["WSO2_SERVER"]   = self.server
        settings.clean()
        return settings.getAsData()

    def add_user(self, userName: Union[str, dict], credential: str = None, roles : str = None, requirePasswordChange : bool = False) -> Union[None, dict]:
        self.last_operation = "Add User : " + str(userName)
        roleList = roles
        if (isinstance(userName, dict)):
            user = copy.deepcopy(userName)
            userName   = user["name"] if ("name" in user) else "NameError"
            credential = user["credential"] if ("credential" in user) else (str(credential) if credential else userName)
            roleList   = user["role"]       if ("role" in user) else str(roleList)
            requirePasswordChange = user["requirePasswordChange"] if ("requirePasswordChange" in user) else requirePasswordChange
        if (not credential) : credential = userName
        if (roleList.lower() in ["creator", "apicreator", "publisher", "apipublisher"] ) :
            roleList = str(apiCreatorRoles)
        elif (roleList.lower() in ["monitoring", "apimonitoring"]) :
            roleList = str(apiMonitoring)
        elif (roleList.lower() in ["admin", "apiadmin"]) :
            roleList = str(apiAdminRoles + apiConsumerRoles + apiCreatorRoles + apiMonitoring)
        elif (roleList.lower() in ["consumer", "apiconsumer", "client", "apiclient"]) :
            roleList = str(apiConsumerRoles)
        else :
            self.last_operation_error   = 600
            self.last_operation_error   = "Error"
            self.last_operation_details = "Add User Error - Invalid Role : " + str(roleList)
            logger.error("Add User Error - Invalid Role : " + str(roleList))
            return None
        roleList = str(roleList).strip("[").strip("]")
        logger.info("User : "       + str(userName))
        logger.info("Credential : " + str(credential))
        logger.info("RoleList : "   + str(roleList).strip("[").strip("]"))
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
        if (self.is_user(userName)) :
            self.delete_user(userName)
        res = self.handle_request(headers, payload_xml)
        if (self.isError()) :  # pragma: no cover
            logger.info("Add User Error : " + "\n" + self.getError())
            return None
        logger.info("Added User : " + "\n" + userName)
        user = self.get_user(userName)
        user["credential"] = credential
        user["requirePasswordChange"] = requirePasswordChange
        return user

    def list_users(self) -> Union[None, str]:
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
        return str(ut.textToList(res))

    def backup_users(self) -> Union[None, dict]:
        ulist = list()
        for user in ut.textToList(self.list_users()):
            ulist.append(self.get_user(user))
        directory = BACKUP_DIRECTORY + os.sep + ut.timestamp() + "_ws_users"
        filename = directory + os.sep + "ws_users.json"
        ut.safeCreateDir(directory)
        logger.info("BackUp File : " + filename)
        ut.saveDataFile(ulist, filename)
        return ut.to_json(ulist)

    def get_user(self, userName: str) -> Union[None, dict]:
        if (isinstance(userName, dict)):
            userName = userName["name"] if ("name" in userName) else "NameError"
        if (not self.is_user(userName)) : return None
        wso2_roles = self.get_user_roles(userName)
        role = self.get_role(userName)
        user =  { "name" : userName, "role" : role, "wso2_roles" : wso2_roles }
        logger.info("Get User : "+userName + "\n" + ut.to_json(user))
        return user

    def delete_user(self, userName: str) -> Union[None, dict]:
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

    def isError(self) -> bool:
        return (self.last_operation_code >= 299)

    def getError(self) -> str:
        errorText =             "Code     : "+str(self.last_operation_code)     + "\n"
        errorText = errorText + "Response : "+str(self.last_operation_response) + "\n"
        errorText = errorText + "Details  : "+str(self.last_operation_details)  + "\n"
        return (errorText)

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
            errorText = "Code     : " + str(self.last_operation_code) + "\n"
            errorText = errorText + "Response : " + str(self.last_operation_response) + "\n"
            errorText = errorText + "Fault    : " + str(self.last_operation_error) + "\n"
            errorText = errorText + "Details  : " + str(self.last_operation_details) + "\n"
            self.setError(errorText)
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

        return self.last_operation_response

    # Interface functions
    def create(self, entity: Union[str, dict], backup: bool = True) -> Union[dict, None]:
        entity = super(FileDataStore, self).create(entity=entity, backup=backup)
        if (self.isError()): return None
        return self.add_user(entity)

    def list(self, names: bool = False, ids: bool = False, count: bool = False) -> Union[list, None, int]:
        self.resetError()
        users_list = self.list_users()
        if (self.isError()):  return None
        if (count):
            return len(users_list)
        if (names):
            user_names = list()
            for user in users_list:
                user_names.append(user[self.name_att])
            return user_names
        if (ids):
            user_ids = list()
            for user in users_list:
                user_ids.append(user[self.id_att])
            return user_ids
        return users_list

    def id_by_name(self, idName: str) -> Union[str, None]:
        self.resetError()
        entry_list = self.list_users()
        if (self.isError()):  return None
        for entry in entry_list:
            if (entry[self.name_att] == idName): return entry[self.id_att]
            if (entry[self.id_att] == idName):   return entry[self.id_att]
        return None

    def name_by_id(self, idName: str) -> Union[str, None]:
        self.resetError()
        entry_list = self.list_users()
        if (self.isError()):  return None
        for entry in entry_list:
            if (entry[self.name_att] == idName): return entry[self.name_att]
            if (entry[self.id_att]   == idName): return entry[self.name_att]
        return None

    def desc_by_idname(self, idName: str) -> Union[str, None]:
        self.resetError()
        entry_list = self.list_users()
        if (self.isError()):  return None
        for entry in entry_list:
            if (entry[self.name_att] == idName): return entry[self.desc_att]
            if (entry[self.id_att] == idName):   return entry[self.desc_att]
        return None

    def exist(self, idName: str) -> bool:
        return self.is_user(self.id_by_name(idName))

    def get(self, idName: str = None, name: str = None, identifier: str = None) -> Union[dict, None]:
        entity_id = super(DataStoreInterface, self).get(idName=idName, name=name, identifier=identifier)
        if (not entity_id): return None
        return self.get_user(entity_id)

    def update(self, entity: Union[str, dict], backup: bool = True) -> Union[dict, None]:
        super(FileDataStore, self).update(entity=entity, backup=backup)
        if (self.isError()): return None
        return self.update(entity, backup)

    def delete(self, idName: str = None, name: str = None, identifier: str = None, backup: bool = True) -> Union[dict, None]:
        entry = super(FileDataStore, self).delete(idName=idName, name=name, identifier=identifier, backup=backup)
        if (self.isError()): return None
        return self.delete_user(entry)

    def delete_all(self, backup: bool = True) -> Union[list, None]:
        self.resetError()
        all_errors = ""
        entries = list()
        if (backup):
            self.dump_all()
        for entry_id in self.list(ids=True):
            entry = self.delete(identifier=entry_id, backup=False)
            if (entry): entries.append(entry)
            if (self.isError()):
                all_errors = all_errors + "\n" + self.getError()
        if (all_errors != ""):
            self.setError(all_errors)
        logger.info("WS02 Store Deleted all : [" + self.entity_type + "]")
        return entries

    def dump_all(self, filename: str = None, directory: str = BACKUP_DIRECTORY) -> dict:
        self.resetError()
        entries = self.list()
        store = dict()
        store["desc_att"] = self.desc_att
        store["name_att"] = self.name_att
        store["service"]  = self.service
        store["entity"]   = self.entity_type
        store["count"]    = len(entries) if (entries) else 0
        store["entries"]  = entries if (entries) else []
        if (not filename):
            ut.safeCreateDir(directory)
            filename = directory + os.sep + self.entity_type + "_dump.json"
        ut.saveJsonFile(store, filename)
        logger.info("Store [" + self.entity_type + "] Dumped in file : " + filename)
        return store

    def store_file(self, filename: str = None, directory: str = None) -> dict:
        global STORE_DIRECTORY
        if (not directory) : directory = STORE_DIRECTORY
        return self.dump_all(filename, directory)

    def load_file(self, filename: str = None, directory: str = None) -> dict:
        global STORE_DIRECTORY
        if (not directory) : directory = STORE_DIRECTORY
        entry_list = super(FileDataStore, self).load_file(filename=filename, directory=directory)
        for entry in entry_list:
            self.update(entry)
        logger.info("Loaded File  : " + filename)
        return self.cache


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

    def category_list(self, service="admin"):
        self.handle_request("LIST", "api-categories", service=service)
        if (self.r_code == 200) and (self.r_text) :
            return json.loads(self.r_text)
        return None

    def category_get(self, category_id, service="admin"):
        # self.handle_request("GET", "api-categories", entry=category_id)
        self.handle_request("LIST", "api-categories", service=service)
        if (self.r_code == 200) and (self.r_text) :
            cat_list = json.loads(self.r_text)
            for elem in cat_list["list"] :
                if (elem["id"]   == category_id): return elem
                if (elem["name"] == category_id): return elem
        return None

    def category_get_id(self, category_id, service="admin"):
        # self.handle_request("GET", "api-categories", entry=category_id)
        self.handle_request("LIST", "api-categories", service=service)
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

    def api_list(self, names : bool = False, names_versions : bool = False, ids : bool = False, versions: bool = False):

        self.handle_request("LIST", "apis?limit=2000", service="publisher")
        if (self.hasData()) :
            if (names) :
                names = []
                for api in self.d_data.getAsData()["list"] :
                    names.append(api["name"]+"/"+api["version"])
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
        self.handle_request("POST", "apis/change-lifecycle?apiId="+api_id+"&action=Publish", service="publisher")
        if (self.r_code == 200) and (self.r_text) :
            return json.loads(self.r_text)
        return None

    def api_get(self, api_id):
        self.handle_request("GET", "apis", entry=api_id, service="publisher")
        if (self.r_code == 200) and (self.r_text) :
            return json.loads(self.r_text)
        return None

    def api_get_swagger(self, api_id):
        self.handle_request("GET", "apis", entry=api_id+"/swagger", service="publisher")
        if (self.r_code == 200) and (self.r_text) :
            return json.loads(self.r_text)
        return None

    def api_get_thumbnail(self, api_id):
        self.handle_request("GET", "apis", entry=api_id+"/thumbnail", service="publisher")
        if (self.r_code == 200) and (self.r_text) :
            return json.loads(self.r_text)
        return None

    def api_get_policies(self, api_id):
        self.handle_request("GET", "apis", entry=api_id+"/subscription-policies", service="publisher")
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


class Wso2Provisioning():

    def __init__(self, service : str = "file"):
        self.service           = service
        self.ws_usermanager    = Wso2UsersManager()
        self.ws_apimanager     = Wso2ApiManager()

    def error(self, text):
        logger.error("Api not found : "+text)
        return text

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
        api_dir     = DATA_DIRECTORY+os.sep+"templates"+os.sep+"apis"+os.sep+model
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
        rc = self.ws_apimanager.api_create(api_desc_json, api_swagger+".zip", publish=publish)
        if (rc == None) : return self.ws_apimanager.getError()
        return rc

    def provisionCategory(self, categoryName : str, dataStore: str ="file") -> bool:
        if (categoryName.upper() == "ALL"):
            cat_store = StoreManager().getStore(name="Categories", store_type=dataStore)
            catList   = cat_store.list(names=True)
            rc = True
            for categoryName in catList:
                rc = rc and self.provisionCategory(categoryName)
            return rc
        logger.info("Provisioning Category : "+categoryName)
        cat_store = StoreManager().getStore(name="Categories", store_type=self.service)
        category  = cat_store.get(categoryName)
        if (not category): return self.error("Api not found : "+categoryName)
        # Get Category Details
        cat_name = category["CategoryName"]
        # Create Context / Maybe load other policies
        rendering_context = category
        # Render Category Descriptor for WS02
        cat_dir     = DATA_DIRECTORY+os.sep+"templates"+os.sep+"categories"
        desc_template = cat_dir+os.sep+"category_create.json"
        cat_desc_file = cat_dir+os.sep+cat_name+"_desc.json"
        ut.Template.renderFile(desc_template, cat_desc_file, rendering_context)
        cat_desc_json = ut.loadDataFile(cat_desc_file)
        logger.info("WSO2 Category Descriptor : "+ut.to_json(cat_desc_json))
        # Create Category in WSO2
        rc = self.ws_apimanager.category_create(cat_desc_json)
        if (rc == None) : return self.ws_apimanager.getError()
        return rc

    def publishAPI(self, apiName: str) -> bool:
        pass

    def unpublishAPI(self, apiName: str) -> bool:
        pass

    def createUser(self, userName: str) -> bool:
        pass

    def createApplication(self, appName: str, user) -> bool:
        pass

    def subscribeAppToApi(self, apiName: str) -> bool:
        pass

    def extractWso2Apis(self, idName : str = "all", dataStore : str = None) -> list:
        wam  = Wso2ApiManager()
        apil = wam.api_list()
        dirname  = "data"+os.sep+"nef-apis-dump"
        ut.safeCreateDir(dirname)
        api_list = list()
        for api in apil["list"] :
            if (idName.lower() != "all"):
                if (idName != api["id"]): continue
                if (idName != api["name"]+"-"+api["version"]): continue
                if (idName != api["name"]+"/"+api["version"]): continue
                if (idName != api["name"]): continue
            id = api["id"]
            apiname = api["name"]+"-"+api["version"]
            logger.info("extractWso2Apis : "+str(apiname)+" : "+id)
            api_dir = dirname+os.sep+apiname
            ut.safeCreateDir(api_dir)
            res = wam.api_get(id)
            ut.saveDataFile(res, api_dir+os.sep+"api_desc.json")
            res = wam.api_get_swagger(id)
            ut.saveDataFile(res, api_dir+os.sep+"swagger.json")
            res = wam.api_get_thumbnail(id)
            ut.saveDataFile(res, api_dir+os.sep+"thumbnail.json")
            res = wam.api_get_policies(id)
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
### Factory Settings
###


class FactoryLoader:

    def __init__(self, service):
        self.service  = service
        self.path_dir = None

    def raise_error(self, text):
        logger.error(text)
        raise Exception(text)

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
            server.delete_all(backup=backup)
        return True

    def delete_all(self, entity : Union[str, list, None] = None, backup : bool = False, delete_all : bool = True) -> bool:
        return self.backup(entity=entity, backup=backup, delete_all=delete_all)

    def b64file_handler(self, entry : dict, pathname : str = None) -> dict:
        if (not pathname):
            pathname = ut.get_cwd_directory()
        for key in entry:
            val = entry[key]
            if isinstance(val, str) and val.startswith("@b64file:"):
                b64data  = re.sub("@b64file:.*:", "", val)
                no_data = True if (b64data == "") else False
                filename = re.sub("@b64file:", "", val)
                filename = re.sub(":.*$", "", filename)
                filepathname = pathname + os.sep + filename
                logger.info("Loading b64file : "+filepathname)
                if (not ut.safeFileExist(filepathname)):
                    if (no_data):
                        self.raise_error("File not found : " + filepathname)
                    else:
                        logger.error("File not found : " + filepathname)
                        entry[key] = val
                else:
                    entry[key] = "@b64file:" + filename + ":" + ut.to_file_2_b64(filepathname)
            if isinstance(val, dict):
                entry[key] = self.b64file_handler(val, pathname)
        return entry

    def entry_loader(self, entry: dict, dir_path : str=None, entity_type: str=None, pathname : str=None, only_entity : str=None) -> Union[None, dict]:
        logger.info("Loading : \n" + ut.to_json(entry))
        if ((entity_type == None) and ("entity" in entry)):
            entity_type = entry["entity"]
        if (not entity_type):
            # No entity type Specified
            text = "No entity type specified for entry in ["+str(pathname)+"]: \n" + ut.to_json(entry)
            logger.error(text)
            raise Exception(text)
        if ((only_entity and only_entity.lower() == "all")):
            pass
        elif ((only_entity) and (str(only_entity).lower() != str(entity_type).lower())):
            text = "Not loading entity type ["+str(entity_type)+"]: \n" + ut.to_json(entry)
            logger.info(text)
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

    def get_server(self, data : dict, pathname : str, entity : str = None):
        if (not data):
            # Invalid json or yaml
            logger.error("Invalid json or yaml Content : "  + pathname)
            raise Exception("Invalid json or yaml Content : " + pathname)
        if (not self.service):
            # No Service Specified
            text = "No service specified for entry : " + str(pathname) + \
                   "\n Service : " + str(self.service) + \
                   "\n" + ut.to_json(data)
            logger.error(text)
            raise Exception(text)
        if (not entity and "entity" in data) :
            entity   = data["entity"]
        if (not entity):
            # No entity Specified
            text = "No entity specified for entry : " + str(pathname) + \
                   "\n entity : " + str(entity) + \
                   "\n" + ut.to_json(data)
            logger.error(text)
            raise Exception(text)
        server = StoreManager().getStore(entity, self.service)
        if (not server):
            # No StoreManager found
            text = "No Store Manager for entry : " + str(pathname) + \
                   "\n- entity  : " + str(entity) + \
                   "\n- service : " + str(self.service) + \
                   "\n" + ut.to_json(data)
            logger.error(text)
            raise Exception(text)
        return server

    def factory_loader(self, pathname, backup : bool=False, delete_all : bool=False, no_dir : bool=False, only_entity : str=None):
        if (backup):
            self.backup(entity=only_entity)
        if (delete_all):
            self.delete_all(entity=only_entity)
        abs_path = ut.get_abs_path(pathname)
        dir_path = ut.get_directory(abs_path)
        logger.info("Loading Path : " + abs_path)
        added_data = list()
        # Directory
        if (ut.safeDirExist(pathname)):
            if (no_dir):
                return self.raise_error("Cannot Load Directory (only files) : " + pathname)
            logger.info("Loading Directory : "  + pathname)
            # All json Files in directory
            logger.info("Scanning JSON Files in : "  + pathname)
            for file in ut.safeListFiles(pdir=pathname, file_ext=".json", keepExt=True):
                added_data = added_data + self.factory_loader(file)
            # All yaml Files in directory
            logger.info("Scanning YAML Files in : "  + pathname)
            for file in ut.safeListFiles(pdir=pathname, file_ext=".yaml", keepExt=True):
                added_data = added_data + self.factory_loader(file)
            return
        # Specific File
        if (not ut.safeFileExist(pathname)):
            self.raise_error("File not found : "  + pathname)
        if (ut.get_extension(pathname).lower() not in [".json", ".yaml"]):
            return self.raise_error("Cannot Load File (only json or yaml files) : " + pathname)
        data = ut.loadFileData(pathname)
        if (not data):
            # Invalid json or yaml
            self.raise_error("Invalid json or yaml Content : "  + pathname)
        logger.info("Loading : " + ut.to_json(data))
        if ("entity" in data) :
            # Single Entry to store
            if ("entry" in data):
                rd = self.entry_loader(data["entry"], entity_type=data["entity"], dir_path=dir_path, only_entity=only_entity)
                if (rd) : added_data.append(rd)
            # All Entries to same store
            elif ("entries" in data):
                for entry in data["entries"]:
                    rd = self.entry_loader(entry, entity_type=data["entity"], dir_path=dir_path, only_entity=only_entity)
                    if (rd): added_data.append(rd)
            else:
                self.raise_error("No \"entries\" in data : "+str(pathname)+"\n" + ut.to_json(data))
        elif ("entries" in data) :
            # Multiples Entries to different stores
            for entry in data["entries"]:
                rd = self.entry_loader(entry, dir_path=dir_path, only_entity=only_entity)
                if (rd) : added_data.append(rd)
        else:
            for entity_type in StoreManager.list_store_entities():
                if ((entity_type.upper() in data) and (isinstance(data[entity_type.upper()], list))):  # Save Format
                    for entry in data[entity_type.upper()]:
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
                    if (not ut.safeFileExist(file)):
                        self.raise_error("File Not Found : " + file)
                    logger.info("Including File : " + file)
                    added_data = added_data + self.factory_loader(file)
        if (len(added_data) == 0):
            self.raise_error("Invalid File Content (not entry found): " + pathname)
        return added_data

FileStoreCache = dict()
RestStoreCache = dict()
Wso2StoreCache = dict()

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

    def loadStores(self, storefile : str = None) -> dict:
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
            file = True if (file.lower() in ["file", "fs", "filestore"]) else False
        for store_key in self.stored :
            if (self.stored[store_key]["name"].lower()   == name.lower()): name = store_key
        for store_key in self.stored:
            if (self.stored[store_key]["entity"].lower() == name.lower()): name = store_key
        if (name not in self.stored): return None
        store = self.stored[name]
        if (store_type == "") :
            if (file): store_type = "file"
            else :     store_type = "rest"
        if (store_type.lower() not in ["file" , "rest" , "wso2"]):
            logger.error("getStore : invalid store type : "+str(store_type))
            return None
        if (store_type.lower() == "file"):
            if (store["entity"] in FileStoreCache) :
                return FileStoreCache[store["entity"]]
            filestore = FileDataStore(entity_type=store["entity"], name_att=store["name_att"], desc_att=store["desc_att"], service=store["service"])
            FileStoreCache[store["entity"]] = filestore
            return filestore
        elif (store_type.lower() == "rest") :
            if (store["entity"] in RestStoreCache) :
                return RestStoreCache[store["entity"]]
            reststore = RestDataStore(entity_type=store["entity"], name_att=store["name_att"], desc_att=store["desc_att"], service=store["service"])
            RestStoreCache[store["entity"]] = reststore
            return reststore
        elif (store_type.lower() == "wso2") :
            key = "wso2_" + name
            if (key in Wso2StoreCache) :
                return Wso2StoreCache[key]
            if (name.lower() in ["users", "ws users", "wso2 users", "ws_users"]):
                wso2store = Wso2UsersManager()
            else:
                logger.error("getStore : invalid wso2 store name : " + str(name))
                return None
            Wso2StoreCache[key] = wso2store
            return wso2store

    @staticmethod
    def get_entity(entity : str) -> str:
        if (entity.lower().startswith("ws")) :
            entity = re.sub(" ", "_", entity.lower().strip("s")) + "s"
        entity = re.sub("^.. ", "", str(entity))
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
        if (attribute not in store) : return None
        return store[attribute] if store else None

    @staticmethod
    def list_store_entities(store_file : str = None, lower : bool = False) -> list:
        global STORES_FILE
        if (not store_file) : store_file = STORES_FILE
        stores = StoreManager.check_stores(store_file)
        entity_list = list()
        for store in stores["stores"]:
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
            logger.error("Invalid json or yaml content : "    + store_file)               # pragma: no cover
            raise Exception("Invalid json or yaml content : " + store_file)               # pragma: no cover
        if (("stores" not in stores)):
            logger.error("No \"stores\" in : " + store_file)                              # pragma: no cover
            raise Exception("No \"stores\" in : " + store_file)                           # pragma: no cover
        for store in stores["stores"]:
            if (("service" not in store)):
                logger.error("No \"service\" in store : " + store_file)                   # pragma: no cover
                raise Exception("No \"service\" in store : " + store_file)                # pragma: no cover
            if (("entity" not in store)):
                logger.error("No \"entity\" in store : " + store_file)                    # pragma: no cover
                raise Exception("No \"entity\" in store : " + store_file)                 # pragma: no cover
            if (("name_att" not in store)):
                logger.error("No \"name_att\" in store : " + store_file)                  # pragma: no cover
                raise Exception("No \"name_att\" in store : " + store_file)               # pragma: no cover
            if (("desc_att" not in store)):
                logger.error("No \"desc_att\" in store : " + store_file)                  # pragma: no cover
                raise Exception("No \"desc_att\" in store : " + store_file)               # pragma: no cover
            if (("name" not in store)):
                logger.error("No \"name\" in store : " + store_file)                      # pragma: no cover
                raise Exception("No \"name\" in store : " + store_file)                   # pragma: no cover
        return stores

    @staticmethod
    def check_entry(entry: dict):
        if (("service" not in entry)):
            logger.error("No \"service\" in entry : " + json.dumps(entry, indent=2))      # pragma: no cover
            raise Exception("No \"service\" in entry : " + json.dumps(entry, indent=2))   # pragma: no cover
        if (entry["service"].lower() not in StoreManager.serviceList):
            logger.error("Unknown \"service\" in entry : " + entry["service"])            # pragma: no cover
            raise Exception("Unknown \"service\" in entry : " + entry["service"])         # pragma: no cover
        if (("entity" not in entry)):
            logger.error("No \"entity\" in entry : " + json.dumps(entry, indent=2))        # pragma: no cover
            raise Exception("No \"entity\" in entry : " + json.dumps(entry, indent=2))     # pragma: no cover
        if (entry["entity"].lower() not in StoreManager.list_store_entities(lower=True)):
            logger.error("Unknown \"entity\" in entry : " + entry["entity"])               # pragma: no cover
            raise Exception("Unknown \"entity\" in entry : " + entry["entity"])            # pragma: no cover
        if (("name_att" not in entry)):
            logger.error("No \"name_att\" in entry : " + json.dumps(entry, indent=2))      # pragma: no cover
            raise Exception("No \"name_att\" in entry : " + json.dumps(entry, indent=2))   # pragma: no cover
        if (("desc_att" not in entry)):
            logger.error("No \"desc_att\" in entry : " + json.dumps(entry, indent=2))      # pragma: no cover
            raise Exception("No \"desc_att\" in entry : " + json.dumps(entry, indent=2))   # pragma: no cover
        if (("entry" not in entry) and ("entries" not in entry)):
            logger.error("No \"entry\" or \"entries\" in entry : " + json.dumps(entry, indent=2))     # pragma: no cover
            raise Exception("No \"entry\" or \"entries\" in entry : " + json.dumps(entry, indent=2))  # pragma: no cover
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
        file_service = True if (service.lower() == "fs") else False
        store = StoreManager().getStore(name=resource, file=file_service)
        if (not store) : return "No Store / Description"
        return store.desc_by_idname(idName)

    @staticmethod
    def get_identifier(entity: str, idName : str):
        resource = StoreManager.get_entity(entity)
        service  = re.sub(" .*$", "", str(entity))
        file_service = True if (service.lower() == "fs") else False
        store = StoreManager().getStore(name=resource, file=file_service)
        if (not store) : return "No Store / Identifier"
        return store.id_by_name(idName)

    @staticmethod
    def get_name(entity: str, idName : str):
        resource = StoreManager.get_entity(entity)
        service  = re.sub(" .*$", "", str(entity))
        file_service = True if (service.lower() == "fs") else False
        store = StoreManager().getStore(name=resource, file=file_service)
        if (not store) : return "No Store / Name"
        return store.name_by_id(idName)

    @staticmethod
    def store_back_up(service: str="file", resource : str="all", operation="unknown"):
        global BACKUP_DIRECTORY
        filename  = BACKUP_DIRECTORY + os.sep + ut.safeTimestamp() + "_" + service + "_all_stores.json"
        return StoreManager.store_save(service=service, resource=resource, save_file=filename, operation="back_up "+operation)

    @staticmethod
    def store_save(service: str="file", resource : str="all", save_file : str=None, operation="save"):
        resources = list()
        if (resource == "all"):
            resources = StoreManager.list_store_entities()
        elif (resource.lower() in StoreManager.list_store_entities(lower=True)):
            resources.append(resource)
        else:
            logger.error("Save : Unknown Resource : "+resource)
            return None
        all_data = dict()
        for res in resources :
            server = StoreManager().getStore(res, service)
            all_data[res] = server.list()
        sys_data = ut.get_sys()
        details = { "operation" : operation, "service" : service, "resources" : resources,
                    "timestamp" : ut.timestamp(), "configuration": ut.getCurrentConfiguration().getAsData(),
                    "status" : "success"   , "system" : sys_data, "filename" : save_file}
        all_data["__details__"] = details
        ut.saveJsonFile(all_data, save_file)
        return ut.to_json(details)


LOCAL_SERVICE     = ["LOCAL", "FILES", "FS"]
DATASTORE_SERVICE = ["AEP", "REST", "DS"]
WSO2_SERVICE      = ["WSO2", "APIG", "WS"]
SERVICES          = LOCAL_SERVICE + DATASTORE_SERVICE + WSO2_SERVICE

AEP_CATALOG_RESSOURCES = ["PROVIDERS", "ARTICLES", "CATEGORIES", "COLLECTIONS", "APIS", "API_BUNDLES"]
AEP_SUBSCRIPTION_RESSOURCES = ["SUBSCRIPTIONS", "API_CONSUMERS"]
AEP_APPLICATION_USER_PROFILES_RESSOURCES = ["ACCOUNTS", "SERVICES", "CONTACTS", "ROLES", "INDUSTRIES", "USECASES"]
AEP_RESSOURCES = AEP_CATALOG_RESSOURCES + AEP_APPLICATION_USER_PROFILES_RESSOURCES + AEP_SUBSCRIPTION_RESSOURCES

APIM_RESSOURCES = ["APIS", "POLICIES", "CATEGORIES", "PRODUCTS"]
DEVM_RESSOURCES = ["APPLICATIONS", "SUBSCRIPTIONS"]
ADM_RESSOURCES  = ["USERS", "SETTINGS"]
WSO2_RESSOURCES = APIM_RESSOURCES + DEVM_RESSOURCES + ADM_RESSOURCES

AEPCTL_COMMANDS = ["HELP", "CONFIG", "CFG", "C", "VERBOSE", "V", "DS", "FS", "WS", "EXIT", "UI", "U", "BROWSER", "BR"]

"""

# Admin Wso2UsersManager

 add_user(self, userName: str, credential: str, roleList : str, requirePasswordChange : bool = False):
 list_users(self):
 delete_user(self, userName: str):
 is_user(self, userName: str):
 get_user_roles(self, userName: str):

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
        if (command  != ""): text = text + command.lower() + " "
        if (text     != ""): text = text + ": "
        error_text = text + message if (message) else text + " - Error."
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
    def browse(resource, entry, idName: str = "") -> str:  # pragma: no cover
        name = str(resource).lower() + " " + str(idName)
        utg.dataBrowserForm(data=ut.SuperDict(entry, name=name).clean(), style="TREE",
                            formats_choices=["Json", "Yaml", "Flat"], read_only=True,
                            name=name, index_prefix=resource.capitalize() + " ").run()
        return AepCtl.print(resource, entry, idName)

    @staticmethod
    def display(resource, entry, idName) -> str:  # pragma: no cover
        name = str(resource).lower() + " " + str(idName)
        utg.dataBrowserForm(data=ut.SuperDict(entry, name=name).clean(), style="TREE",
                            formats_choices=["Json", "Yaml", "Flat"], read_only=True,
                            name=name, index_prefix=resource.capitalize() + " ").run()
        return AepCtl.print(resource, entry, idName)

    @staticmethod
    def handle_output(entry, resource, command, idName: str = "", fileName: str = None) -> str:
        logger.info("handle_output " + " command : " + command + " idName : " + idName + " fileName : " + str(fileName))
        yaml_text = "\n" + ut.to_yaml(entry, indent=2)
        json_text = "\n" + ut.to_json(entry, indent=2)
        if ("file" in idName.strip()) :
            fileName = re.sub("^file", "", idName.strip())
            idName = "file"
        if (command.upper() == "DISPLAY"):  # pragma: no cover
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
    def aepctlui():
        aepctlui.MainGUI().run()

    @staticmethod
    def display_help():
        console = Console()
        with open("aepctl.md", "r+") as help_file:
            console.print(Markdown(help_file.read()))

    @staticmethod
    def display_config():
        ut.Term.print_green(str(ut.getCurrentConfiguration()))

    @staticmethod
    def prompt_list_to_dict(elist: list, append: dict = None) -> dict:
        ldc = append if (append) else dict()
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
            "delete": {"<id>", "<name/version>", "help"},
            "display": {"<id>", "<name/version>", "help"},
            "details": {"<id>", "all", "help"},
            "browse": {"<id>", "all", "help"}
        },
        "policies": {
            "help": None,
            "list": {"entries", "count", "names", "ids", "help"},
            "browse": { "all", "help"},
            "get": {"<id>", "help"},
            "display": {"<id>", "help"}
        },
        "categories": {
            "help": None,
            "list": {"entries", "names", "ids", "help"},
            "browse": { "all", "help"},
            "get": {"<id>", "help"},
            "display": {"<id>", "help"},
            "create": {"<name>": {"<description>"}},
            "update": {"<name>": {"<description>"}},
            "delete": {"<name>", "help"}
        },
        "products": {
            "help": None,
            "list": {"entries", "count", "names", "ids", "help"},
            "browse": { "all", "help"},
            "get": {"<id>", "help"},
            "display": {"<id>", "help"}
        },
        "users": {
            "help": None,
            "list"    :  { "users", "names", "roles", "count" },
            "browse"  :  None,
            "get"     :  { "<name>",  "help"  },
            "display" :  { "<name>",  "help"  },
            "roles"   :  { "<name>",  "help"  },
            "delete"  :  { "<name>",  "help"  },
            "create"  :  { "apiCreator"    : { "<name>" },
                           "apiConsumer"   : { "<name>" },
                           "apiAdmin"      : { "<name>" },
                           "apiMonitoring" : { "<name>" },
                         },
            "backup": None,
        },
        "browser": { "publisher", "apim", "dev", "portal", "mgt", "console" },
    }

    @staticmethod
    def handle_ws02_command(arguments):

        logger.info("handle_ws02_command")

        resource = arguments["RESSOURCE"]
        command  = arguments["COMMAND"]
        idName   = arguments["ID"]
        payload  = arguments["PAYLOAD"]

        admm = Wso2UsersManager()
        apim = Wso2ApiManager()
        devm = Wso2ApiDevManager()

        # All Help Levels
        if (command in ["HELP"]):  # <resource>  help
            return AepCtl.help(resource, AepCtl.wso2_commands)
        if (resource in ["HELP"]):  # <resource>  help
            return AepCtl.help(resource, AepCtl.wso2_commands)
        if (idName.upper() in ["HELP"]):  # <resource> <command> help
            return AepCtl.help(resource, command, AepCtl.wso2_commands)

        if (command in ["BROWSER", "BR"]):  # Open Portal
            logger.info("Open Portal   = " + str(resource))
            res = wso2_browser(resource)
            return AepCtl.print("BROWSER", res, idName)

        # settings_get(self):
        if (resource == "SETTINGS"):
            # settings_get(self):
            if (command in ["GET", "DISPLAY"]):  # settings get|display
                if (idName.upper() in ["APIM", "PUBLISHER_PORTAL"]):
                    entry = apim.settings_get()
                    if (apim.isError()):  entry["error"] = apim.getError()
                elif (idName.upper() in ["ADMIN", "WSO2"]):
                    entry = admm.settings_get()
                    if (admm.isError()):  entry["error"] = admm.getError()
                elif (idName.upper() in ["DEV", "DEVELOPER_PORTAL"]):
                    entry = devm.settings_get()
                    if (devm.isError()):  entry["error"] = devm.getError()
                else:
                    return AepCtl.error(resource, command, "Unkown idName : " + idName)
                if (command == "GET"):  # settings display
                    return AepCtl.print(resource, entry, idName)
                elif (command == "DISPLAY"):  # settings display
                    return AepCtl.display(resource, entry, idName)
            else:
                return AepCtl.error(resource, command, "Unkown command : " + command)

        # Publisher Wso2ApiManager
        if (resource == "APIS"):
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
            if (command in ["DELETE", "ERASE"]):  # apis list
                if ("/" in idName):  # apis get|display name/version
                    apid = apim.api_id_by_name(name=idName)
                else:  # apis get|display id
                    apid = idName
                delete_res = apim.api_delete(api_id=apid)
                if (apim.isError()): return AepCtl.error(resource, command, apim.getError())
                return AepCtl.print(resource, delete_res)
        if (resource == "POLICIES"):
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
        if (resource == "CATEGORIES"):
            # category_get(self, category_id):
            # category_list(self, service="admin"):
            # category_create(self, category: str):
            # category_delete(self, category_id):
            if (command in ["LIST", "BROWSE"]):  # categories list
                elist = apim.category_list(service="admin")
                if (apim.isError()):
                    return AepCtl.error(resource, command, apim.getError())
                if (command == "LIST"):  # category list
                    if (idName.lower() == "count") :
                        return AepCtl.print(resource, elist["count"])
                    elif (idName.lower() == "names"):
                        cat_list = list()
                        for elem in elist["list"] :
                            cat_list.append(elem["name"])
                        return AepCtl.print(resource, cat_list)
                    elif (idName.lower() == "ids"):
                        cat_list = list()
                        for elem in elist["list"] :
                            cat_list.append(elem["id"])
                        return AepCtl.print(resource, cat_list)
                    else:
                        return AepCtl.print(resource, elist["list"])
                if (command == "BROWSE"):  # category browse
                    return AepCtl.browse(resource, elist["list"])
            if (command in ["GET", "DISPLAY"]):  # categories get|display id|name
                entry = apim.category_get(category_id=idName)
                if (command == "GET"):  # category display
                    return AepCtl.print(resource, entry, idName)
                elif (command == "DISPLAY"):  # category display
                    return AepCtl.display(resource, entry, idName)
            if (command in ["CREATE", "UPDATE"]):  # create user
                if (idName.lower() == "-p") :
                    res = apim.category_create(category=ut.loadDataFile(payload))
                else:
                    res = apim.category_create(category=idName, description=payload)
                return AepCtl.print(resource, res)
            if (command in ["DELETE"]):  # delete user
                cat = apim.category_delete(idName)
                return AepCtl.print(resource, cat, idName)
        if (resource == "PRODUCTS"):
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
        if (resource == "APPLICATIONS"):
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
        if (resource == "SUBSCRIPTIONS"):
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
            if (command == "HELP"):  # help
                return AepCtl.help(resource, command, AepCtl.wso2_commands)
            if (command == "BACKUP"):  # back up
                ulist = admm.backup_users()
                return AepCtl.print("users", ulist)
            if (command == "LIST"):  # users list
                if (idName.upper() in [ "COUNT" ]) :
                    return AepCtl.print("users count", len(ut.textToList(admm.list_users())))
                if (idName.upper() in [ "ROLES", "ROLE" ]) :
                    return AepCtl.print("users roles", apiRoles)
                if (idName.upper() in [ "NAMES", "NAME", "IDS", "ID" ]):
                    elist = ut.textToList(admm.list_users())
                    return AepCtl.print("users", elist)
                ulist = list()
                for user in ut.textToList(admm.list_users()):
                    ulist.append(admm.get_user(user))
                return AepCtl.print("users", ulist)
            if (command == "BROWSE"):  # users list
                ulist = list()
                for user in ut.textToList(admm.list_users()):
                    ulist.append(admm.get_user(user))
                return AepCtl.browse("users", ulist)
            if (command == "GET"):  # get user
                user = admm.get_user(idName)
                return AepCtl.print("users", user, idName)
            if (command == "DISPLAY"):  # get user
                user = admm.get_user(idName)
                return AepCtl.display("users", user, idName)
            if (command in [ "CREATE", "UPDATE" ] ):  # create user
                if (idName == "-p") :
                    res = admm.add_user(userName=ut.loadDataFile(payload))
                else:
                    res = admm.add_user(userName=payload, roles=idName)
                return AepCtl.print("users", res)
            if (command in [ "DELETE", "ERASE" ] ):  # delete user
                user = admm.delete_user(idName)
                return AepCtl.print("users", user, idName)

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
    }

    @staticmethod
    def get_aep_commands():
        aep_ressources = AepCtl.prompt_list_to_dict(AEP_RESSOURCES)
        for aep_ressource in aep_ressources:
            aep_ressources[aep_ressource] = AepCtl.ds_commands
        aep_ressources["help"]   = None
        aep_ressources["stores"] = None
        aep_ressources["load"] = {
            "delete_all" : PathCompleter(expanduser=True),  # SystemCompleter(),  # PathCompleter(expanduser=True),
            "merge"      : PathCompleter(expanduser=True),  # SystemCompleter(),  # PathCompleter(expanduser=True),
        }
        return aep_ressources

    FS_COMMANDS = ["LOAD", "SAVE", "IMPORT", "EXPORT", "BACKUP", "RESTORE", "DELETE_ALL"]

    def get_aep_completer(for_service : str = "ds"):  # pragma: no cover
        dcmd = dict()
        if (for_service.lower() == "fs") : dcmd = AepCtl.get_aep_commands()
        if (for_service.lower() == "ds") : dcmd = AepCtl.get_aep_commands()
        if (for_service.lower() == "ws") : dcmd = copy.deepcopy(AepCtl.wso2_commands)
        dcmd = AepCtl.prompt_list_to_dict(AEPCTL_COMMANDS, dcmd)
        dcmd["ws"] = copy.deepcopy(AepCtl.wso2_commands)
        dcmd["fs"] = AepCtl.get_aep_commands()
        dcmd["ds"] = AepCtl.get_aep_commands()
        compl =  NestedCompleter.from_nested_dict(dcmd)
        return  compl

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
            return AepCtl.help(resource, AepCtl.get_aep_commands())
        if (resource in ["HELP"]):  # <command> help
            return AepCtl.help(resource, AepCtl.get_aep_commands())
        if (resource == "STORES"):
            return AepCtl.print(resource, str(StoreManager.list_store_entities()))
        if ((command == "") and (resource == "")):
            return AepCtl.error(resource, command, "No command nor resource specified.", AepCtl.help(resource, AepCtl.get_aep_commands()))
        store = None
        if (resource != "all"):
            try:
                store = StoreManager().getStore(resource, file="file")
            except Exception as ex:
                return AepCtl.error(resource, command, "Store Access Error.", AepCtl.print("resources", str(ex).replace("\\n", "\n")))
            if (not store):
                return AepCtl.error(resource, command, "Invalid Resource.", AepCtl.print("resources", str(StoreManager.list_store_entities())))
        if (command in ["OPENAPI"]):
            openapi = StoreManager.get_openapi(entity=resource)
            return AepCtl.handle_output(openapi, resource, command, idName, fileName="OpenAPI_" + resource + ".yaml")
        elif (command in ["SCHEMA"]):
            schema = StoreManager.get_schema(entity=resource)
            return AepCtl.handle_output(schema, resource, command, idName, fileName="Schema_" + resource + ".yaml")
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
            if (idName.upper() == "ALL"):
                entries = store.delete_all()
                if (store.error()): return AepCtl.error(resource, command, store.error())
                return AepCtl.print(resource, entries)
            else:
                entry = store.delete(idName)
                if (store.error()): return AepCtl.error(resource, command, store.error())
                return AepCtl.print(resource, entry)
        elif (command in ["CREATE", "UPDATE"]):
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
            if (not isinstance(payload, dict)):
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
        elif (command in ["BACKUP"]):
            directory = (idName + " " + str(payload)).strip()
            logger.info("BackUp Dir : "+directory)
            res = StoreManager().store_back_up(resource=resource, service=service)
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
                pathname = (idName + " " + str(payload)).strip()  # ??
            logger.info("Loading : " + pathname)
            logger.info("To      : " + service)
            res = FactoryLoader(service=service).factory_loader(pathname=pathname, delete_all=delete_all, backup=True, no_dir=True, only_entity=resource)
            return AepCtl.print(resource, res)
        elif (command in ["SAVE"]):
            pathname = ut.get_cwd_directory()+os.sep+str(idName).strip()
            pathname = ut.get_basename(pathname)+".json"
            logger.info("Saving : " + pathname)
            res = StoreManager.store_save(service=service, resource=resource, back_up_file=pathname)
            return AepCtl.print(resource, res)
        elif (command in ["EXTRACT"]):
            logger.info("Extracting : " + str(idName))
            wsp = Wso2Provisioning()
            res = wsp.extractWso2Apis(idName, dataStore=service)
            return AepCtl.print(resource, res)
        elif (command in ["PROVISION"]):
            if (resource.upper() not in ["APIS", "CATEGORIES"]):
                return AepCtl.error(resource, command, "Invalid Resource to Provision : "+resource, AepCtl.help(resource, AepCtl.get_aep_commands()))
            wsp = Wso2Provisioning()
            logger.info("Provisioning " + resource + " : " + str(idName))
            if (resource.upper() == "APIS"):
                res = wsp.provisionAPI(idName, dataStore=service)
                return AepCtl.print(resource, res)
            if (resource.upper() == "CATEGORIES"):
                res = wsp.provisionCategory(idName, dataStore=service)
                return AepCtl.print(resource, res)
        else:
            return AepCtl.error(resource, command, "Invalid Command.", AepCtl.help(resource, AepCtl.get_aep_commands()))
        return None

    @staticmethod
    def handle_command(arguments):

        resource = arguments["RESSOURCE"].upper() if (("RESSOURCE" in arguments) and (arguments["RESSOURCE"])) else ""
        command  = arguments["COMMAND"].upper()   if (("COMMAND" in arguments)   and (arguments["COMMAND"]))   else ""
        idName   = arguments["ID"]                if (("ID" in arguments)        and (arguments["ID"]))        else ""
        service  = arguments["SERVICE"].upper()   if (("SERVICE" in arguments)   and (arguments["SERVICE"]))   else "REST"
        entry    = arguments["PAYLOAD"]           if (("PAYLOAD" in arguments)   and (arguments["PAYLOAD"]))   else ""
        entry    = re.sub("\\\"", '"', entry)
        arguments["PAYLOAD"] = entry
        if ((resource.upper() in AEPCTL_COMMANDS) or
            (command.upper()  in AEP_RESSOURCES) or
            (command.upper()  in WSO2_RESSOURCES)):
            tmp_res  = command
            command  = resource.upper()
            resource = tmp_res.upper()
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

        """
        if (arguments["VERBOSE"]):
            ut.Verbose.set_verbose(True)
        else:
            ut.Verbose.set_verbose(False)
        """

        if (command.upper() in ["CONFIG", "CFG", "C"]):
            return AepCtl.display_config()
        elif (command.upper() in ["VERBOSE", "V"]):
            return ut.Verbose.swap_verbose()
        elif (command.upper() in ["UI", "U"]):
            Thread(target=AepCtl.aepctlui).start()
            return "aepctlui"
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
            ut.Term.print_green(read_command_line_args(None, p_usage=True))
            return None


###
### Prompt Completion
###


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
            if (current_context == "fs"): text = "eapctl" + colored("fs", "red") + " > "  # Not compatible with prompt ?
            if (current_context == "fs"): text = HTML("eapctl <IndianRed>"      + current_context + "</IndianRed>" + " > ")
            if (current_context == "ds"): text = HTML("eapctl <MediumSeaGreen>" + current_context + "</MediumSeaGreen>" + " > ")
            if (current_context == "ws"): text = HTML("eapctl <DeepSkyBlue>"    + current_context + "</DeepSkyBlue>" + " > ")
            try:
                command = session.prompt(text, completer=AepCtl.get_aep_completer(current_context), complete_while_typing=True)
                ctrl_c  = False
            except KeyboardInterrupt :   # Capture CTRL-C Reset Line
                if (ctrl_c) : return     # Double CTRL-C Exit
                ctrl_c = True
                continue
        else:
            if (current_context == "fs"): text = "eapctl" + colored("fs", "red")   + " > "  # Not compatible with prompt ?
            if (current_context == "ws"): text = "eapctl" + colored("fs", "green") + " > "  # Not compatible with prompt ?
            if (current_context == "ws"): text = "eapctl" + colored("fs", "blue")  + " > "  # Not compatible with prompt ?
            command = input("eapctl " + current_context + " > ")
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
        res = main(command, interactive=True)
        logger.debug(res)
        # print(str(res))


###
### Main
###


def read_command_line_args(argv, p_usage : bool = False) -> Union[str, dict, None]:
    global CONFIG_FILE

    usage = """
Usage: -h -v -i -c <ConfigurationFile.json> [<service>] [<resource>] [<command>] [<identifier>] [<payload>] -p <PayloadFile.json>
       -h --help        : Usage help 
       -u --ui          : User Interface     
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
Commands  : """ + str(AEPCTL_COMMANDS) + """  
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
        opts, args = getopt.getopt(argv, "huvdc:p:s:fw", ["help", "verbose", "ui", "debug",  "config=", "payload=", "service=", "filestore", "wso2"])
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
        elif opt.lower() in ("-u", "--ui"):
            aepctlui.MainGUI().run()
            return None
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
        ut.Verbose.init_verbose(False)

    logger.info("Command Line Arguments : " + str(argv))
    logger.info("Command Line Args : \n" + json.dumps(args, indent=3))

    AEPCTL_Configuration = ut.init_Configuration(cfg_filename=AEPCTL_Configuration_FileName,  # Default Config FileName
                                                 cmd_line_arg=CONFIG_FILE,                    # Command Line Arg. Config FileName
                                                 env_cfg_var="AEPCTL_CONFIGURATION",          # Env Var with the Config FileName
                                                 default_cfg=def_AEPCTL_Configuration,        # Default Configuration
                                                 tag="AEPCTL Configuration")

    CFG_AEPCTL_ROOT_DIR = AEPCTL_Configuration.get("AEPCTL_ROOT_DIR")
    CFG_AEPCTL_WORK_DIR = AEPCTL_Configuration.get("AEPCTL_WORK_DIR")
    CFG_AEPCTL_HOME_DIR = AEPCTL_Configuration.get("AEPCTL_HOME_DIR")
    set_aepctl_dirs(CFG_AEPCTL_ROOT_DIR, CFG_AEPCTL_WORK_DIR)
    logger.info("AEPCTL_HOME_DIR  : " + str(CFG_AEPCTL_HOME_DIR))
    logger.info("AEPCTL_ROOT_DIR  : " + str(CFG_AEPCTL_ROOT_DIR))
    logger.info("AEPCTL_WORK_DIR  : " + str(CFG_AEPCTL_WORK_DIR))
    # os.chdir(AEPCTL_HOME_DIR)

    return AepCtl.handle_command(args)


if __name__ == '__main__':    # pragma: no cover
    if (len(sys.argv[1:]) == 0):
        # No arguments - interactive session
        interactive_prompt()
    else:
        # Arguments - one time command
        main(argv=sys.argv[1:], interactive=False)


###
### Unit Tests
###


class TestMain(unittest.TestCase):     # pragma: no cover

    def setUp(self) -> None:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def testCommandLineArguments(self):
        main("-v fs providers list names")

    def testInteractive(self):
        command = input("eapctl > ")
        while command != "exit" :
            res = main(command, interactive=True)
            logger.debug(res)
            # print(str(res))
            command = input("eapctl > ")


# Need WSO2 Server to test this
class TestWso2Manager(unittest.TestCase):    # pragma: no cover

    def setUp(self) -> None:
        self.userManager  = Wso2UsersManager()
        self.apiManager   = Wso2ApiManager()
        self.devManager   = Wso2ApiDevManager()
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def test_userManager(self):  # Need WSO2 server to test this
        self.userManager.delete_user("apicreator")
        self.assertEqual(False,             self.userManager.is_user("apicreator"))
        self.assertNotIn("apicreator",      self.userManager.list_users())
        self.assertIsNotNone(self.userManager.add_user(userName="apicreator", roles="apicreator", requirePasswordChange=True))
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
        self.assertIsNotNone(self.userManager.add_user(userName="apiconsumer", roles="apiconsumer", requirePasswordChange=True))
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
        res = main(prefix + "help ")
        self.assertIn("create", res)
        res = main(prefix + "list help")
        self.assertIn("names", res)
        res = main(prefix + "delete apiconsumer")
        res = main(prefix + "get apiconsumer")
        self.assertNotIn("apiconsumer", res)
        res = main(prefix + "list users")
        self.assertNotIn("apiconsumer", res)
        res = main(prefix + "list ")
        self.assertNotIn("apiconsumer", res)
        res = main(prefix + "list names")
        self.assertNotIn("apiconsumer", res)
        res = main(prefix + "list roles")
        self.assertNotIn("apiconsumer", res)
        res = main(prefix + "create apiconsumer apiconsumer")
        self.assertIn("apiconsumer", res)
        res = main(prefix + "get apiconsumer")
        self.assertIn("apiconsumer", res)
        res = main(prefix + "list ")
        self.assertIn("apiconsumer", res)
        res = main(prefix + "delete apiconsumer")
        self.assertIn("apiconsumer", res)
        res = main(prefix + "get apiconsumer")
        self.assertNotIn("apiconsumer", res)
        res = main(prefix + "list ")
        self.assertNotIn("apiconsumer", res)

    def test_policy(self):  # Need WSO2 server to test this
        self.apiManager.authentify()
        self.apiManager.policy_list(policyType="subscription")
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
        self.apiManager.policy_create(policy=policy_create,    policyType="subscription")
        if (not self.apiManager.isError()):
            policy_id = self.apiManager.d_data.get("policyId")
            print(str(policy_id))
            self.apiManager.policy_get(policy_id=policy_id,    policyType="subscription")
            self.apiManager.policy_delete(policy_id=policy_id, policyType="subscription")
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
        backup_entries_list = store.list()
        backup_entries = store.delete_all(backup=backup)
        # self.assertEqual(backup_entries_list, backup_entries)  # too long some times

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
        self.assertIn("Invalid Format : 5", store.getError())

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
        self.assertEqual(entry[id_att],    store.id_by_name(idName=entry[id_att]))
        self.assertEqual(entry[name_att],  store.name_by_id(idName=entry[id_att]))
        self.assertEqual(entry[desc_att],  store.desc_by_idname(idName=entry[id_att]))
        self.assertEqual(entry[id_att],    store.id_by_name(idName=entry[name_att]))
        self.assertEqual(entry[name_att],  store.name_by_id(idName=entry[name_att]))
        self.assertEqual(entry[desc_att],  store.desc_by_idname(idName=entry[name_att]))
        self.assertEqual(None,             store.id_by_name(idName="TT"))
        self.assertEqual(None,             store.name_by_id(idName="TT"))
        self.assertEqual(None,             store.desc_by_idname(idName="TT"))

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
        self.assertEqual("Invalid Format : 5", store.getError())
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
        self.assertEqual("Invalid Format : 5", store.getError())

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
        self.assertEqual(1, store.list(count=True))
        store.delete_all(backup=backup)
        self.assertEqual(0, store.list(count=True))

        openapi = StoreManager().get_openapi(entity=store_entity)
        schema  = StoreManager().get_schema(entity=store_entity)

        # Restore Entries
        for entry in backup_entries :
            store.create(entry, backup=backup)
        entry_list = store.list()
        # It differs because of create which creates new ids. ... to be fixed.
        # self.assertEqual(backup_entries_list, entry_list)

    def generic_commands(self, store : str , new_entry : str, store_type="file", backup : bool=False):  # Need DataStore server to test this
        store    = self.storeManager.getStore(store, file=store_type)
        id_att   = self.storeManager.get_id_att(store.entity_type)
        name_att = self.storeManager.get_name_att(store.entity_type)
        desc_att = self.storeManager.get_desc_att(store.entity_type)

        # Backup Entries
        backup_entries_list = store.list()
        backup_entries      = store.delete_all(backup=backup)
        self.assertEqual(backup_entries_list, backup_entries)

        entry_file_name = ".payload.json"
        entry = ut.loadDataContent(new_entry)
        entry[id_att] = "id"
        ut.saveJsonFile(entry, entry_file_name)

        verbose   = "-v"
        service   = store.entity_type
        ent_type  = "fs " if (store_type.lower() == "file") else "ds "
        prefix = verbose + " " + service + " " + ent_type

        # Delete All
        res = main(prefix + "delete all")
        self.assertIn("[", res)
        res = main(prefix + "list count")
        self.assertIn("0", res)

        # Now should be empty
        res = main(prefix + "list")
        self.assertEqual(res, "[]")
        res = main(prefix + "list ids")
        self.assertEqual(res, "[]")
        res = main(prefix + "list names")
        self.assertEqual(res, "[]")
        res = main(prefix + "list count")
        self.assertEqual(res, "0")

        # Create Entry
        res = main(prefix + "create " + entry_file_name)
        self.assertIn(entry[desc_att], res)
        created_entry = ut.loadDataContent(res)
        res = main(prefix + "list names")
        self.assertIn(entry[name_att], res)
        res = main(prefix + "list ids")
        self.assertIn(created_entry[id_att], res)
        res = main(prefix + "list count")
        self.assertIn("1", res)
        res = main(prefix + "list")
        self.assertIn(entry[name_att], res)
        self.assertIn(created_entry[id_att], res)
        self.assertIn(entry[desc_att], res)

        # Create Entry Errors
        entry_error_file_name = ".payload_error.json"
        ut.saveFileContent("TT", entry_error_file_name)
        res = main(prefix + "create -p " + entry_error_file_name)
        self.assertIn("Cannot JSON/YAML Decode", res)
        ut.saveFileContent("5", entry_error_file_name)
        res = main(prefix + "create -p " + entry_error_file_name)
        self.assertIn("Cannot JSON/YAML Decode", res)

        # Get Testing
        res = main(prefix + "get " + created_entry[id_att])  # by ID
        self.assertIn(entry[name_att], res)
        self.assertIn(created_entry[id_att], res)
        self.assertIn(entry[desc_att], res)
        self.assertEqual(self.no_id(entry, id_att), ut.loadDataContent(self.no_id(res, id_att)))
        res = main(prefix + "get " + created_entry[name_att])  # by Name
        self.assertIn(entry[name_att], res)
        self.assertIn(created_entry[id_att], res)
        self.assertIn(entry[desc_att], res)
        self.assertEqual(self.no_id(entry, id_att), ut.loadDataContent(self.no_id(res, id_att)))

        # Get Entry Errors
        res = main(prefix + "get TT")
        self.assertIn("No such entry : TT", res)

        # Update Entry
        entry_file_name = ".payload.json"
        res = main(prefix + "get " + created_entry[id_att])  # by ID
        entry = ut.loadDataContent(res)
        entry[desc_att] = "New Description"
        ut.saveJsonFile(entry, entry_file_name)

        res = main(prefix + "update -p " + entry_file_name)
        self.assertIn("New Description", res)
        res = main(prefix + "get " + created_entry[id_att])  # by ID
        self.assertIn("New Description", res)

        # Update Entry Errors
        ut.saveFileContent("TT", entry_error_file_name)
        res = main(prefix + "update -p " + entry_error_file_name)
        self.assertIn("Cannot JSON/YAML Decode", res)
        ut.saveFileContent("5", entry_error_file_name)
        res = main(prefix + "update -p " + entry_error_file_name)
        self.assertIn("Cannot JSON/YAML Decode", res)

        update_entry = ut.loadDataFile(entry_file_name)
        update_entry.pop(name_att, None)
        update_entry = ut.saveDataFile(update_entry, entry_file_name)
        res = main(prefix + "update -p " + entry_file_name)
        self.assertIn("is a required property", res)

        # Delete Entry Errors
        res = main(prefix + "delete TT ")
        self.assertIn("No such entry : TT", res)

        # Delete Entry
        res = main(prefix + "delete " + created_entry[id_att])  # by ID
        self.assertIn("New Description", res)
        res = main(prefix + "get " + created_entry[id_att])  # by ID
        self.assertIn("No such entry", res)

        # openapi / schema
        res = main(prefix + "openapi ")
        self.assertIn("components:", res)
        res = main(prefix + "get openapi ")
        self.assertIn("components:", res)
        res = main(prefix + "schema ")
        self.assertIn("$schema:", res)
        res = main(prefix + "get schema ")
        self.assertIn("$schema:", res)

        # help
        res = main(prefix + "help ")
        self.assertIn("help|get", res)
        res = main(prefix + " help get")
        self.assertIn("help|get", res)
        res = main("help ")
        self.assertIn("providers", res)
        res = main("")
        self.assertIn("No command nor resource specified", res)

        # Reset Store
        res = main(prefix + "delete all")
        self.assertIn("[", res)
        res = main(prefix + "list count")
        self.assertIn("0", res)
        res = main(prefix + " list")
        self.assertEqual(res, "[]")
        res = main(prefix + " list ids")
        self.assertEqual(res, "[]")
        res = main(prefix + " list names")
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

    def test_Providers(self, store_type="file", backup:bool = False):
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

    def test_all_file(self):
        self.test_all(store_type="file")


class TestAll(unittest.TestCase):

    def test_all(self):
        # DataStore
        tds = TestDataStore()
        tds.setUp()
        tds.test_all_file()
        tds.test_all_rest()
        # WS02
        tws = TestWso2Manager()
        tws.setUp()
        tws.test_all()
