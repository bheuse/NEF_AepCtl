import json, yaml, ast, traceback, tempfile
from datetime import datetime
from jsonschema import validate, ValidationError
from genson import SchemaBuilder
import jk_commentjson as jsonc
from collections import deque
# import pandas as pd
import uuid as uid
import re, platform, socket, sys, shutil, errno, getopt, glob, subprocess  # psutil
from functools import reduce  # forward compatibility for Python 3
import urllib.parse as p
import flatten_json as fj
import importlib as imp
from importlib.machinery import SourceFileLoader
import inspect
import os
import types
import uncurl
import logging.config
import unittest
from termcolor import colored
import mako.runtime
from mako.template import Template as MakoTemplate
from mako import exceptions
from mako.lookup import TemplateLookup

import Util
import VersionControl as vc
from typing import Union, cast
import webbrowser

# import qprompt
# https://qprompt.readthedocs.io/en/latest/

# import console-menu
# https://github.com/aegirhall/console-menu

# from expiringdict import ExpiringDict
# import io, smtplib, time

import operator
from pprint import pprint
import base64
import datetime

from urllib.parse import urlparse, parse_qs, unquote, quote
from flask import send_file
from werkzeug.utils import secure_filename
import requests

from bs4 import BeautifulSoup
import importlib
import dpath.util
from jsonpath_ng import parse

import logging
logging.basicConfig(format='%(levelname)s:%(name)s:%(message)s', level=logging.INFO)
logger   = logging.getLogger(__name__)
rslogger = logging.getLogger('Query')

ANME_HTTP          = "https"

ANME_ROOT_DIR      = ".."
ANM_ENGINE_DIR     = ANME_ROOT_DIR+os.sep+"anm_engine"

if (not os.path.exists(ANME_ROOT_DIR+os.sep+"etc")):
    # Docker Environment
    ANME_ROOT_DIR = "."
    ANM_ENGINE_DIR = ANME_ROOT_DIR

CONFIG_DIRECTORY   = ANME_ROOT_DIR+os.sep+"etc"
DATA_DIRECTORY     = ANME_ROOT_DIR+os.sep+"etc"
DOC_DIRECTORY      = ANME_ROOT_DIR+os.sep+"doc"
TMP_DIRECTORY      = ANME_ROOT_DIR+os.sep+"tmp"
TEST_DIRECTORY     = ANME_ROOT_DIR+os.sep+"tests"
LOGS_DIRECTORY     = ANME_ROOT_DIR+os.sep+"logs"
FS_DIRECTORY       = ANME_ROOT_DIR+os.sep+"fs"
DB_DIRECTORY       = ANME_ROOT_DIR+os.sep+"db"
SCRIPTS_DIRECTORY  = ANME_ROOT_DIR+os.sep+"scripts"
AWS_DIRECTORY      = ANME_ROOT_DIR+os.sep+"aws"

ANME_NAMESPACE = "ANME:"

NAME_KEY   = "__NAME__"
SOURCE_KEY = "__SOURCE__"

###
### Setup logging configuration
###

CURRENT_LOGGING_CONFIGURATION = DATA_DIRECTORY+os.sep+"logging.json"
DEFAULT_LOGGING_CONFIGURATION = DATA_DIRECTORY+os.sep+"logging_Default.json"
ENV_VAR_LOGGING = "LOGGING_CONFIGURATION"

default_logging_config = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "simple": {
            "format": "%(asctime)s - %(rule_name)s - %(levelname)s - %(message)s"
        }
    },

    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "level": "DEBUG",
            "formatter": "simple",
            "stream": "ext://sys.stdout"
        },

        "info_file_handler": {
            "class": "logging.handlers.RotatingFileHandler",
            "level": "INFO",
            "formatter": "simple",
            "filename": ".."+os.sep+"logs"+os.sep+"system.log",
            "maxBytes": 10485760,
            "backupCount": 2,
            "encoding": "utf8"
        },

        "datagram_handler": {
            "class": "logging.handlers.DatagramHandler",
            "level": "INFO",
            "formatter": "simple",
            "host": "127.0.0.1",
            "port": 9021
        },

        "socket_handler": {
            "class": "logging.handlers.SocketHandler",
            "level": "INFO",
            "formatter": "simple",
            "host": "127.0.0.1",
            "port": 9020
        },

        "error_file_handler": {
            "class": "logging.handlers.RotatingFileHandler",
            "level": "ERROR",
            "formatter": "simple",
            "filename": ".."+os.sep+"logs"+os.sep+"errors.log",
            "maxBytes": 10485760,
            "backupCount": 2,
            "encoding": "utf8"
        }
    },

    "loggers": {
        "my_module": {
            "level": "ERROR",
            "handlers": ["console"],
            "propagate": False
        }
    },

    "root": {
        "level": "INFO",
        "handlers": ["console", "info_file_handler", "error_file_handler", "datagram_handler", "socket_handler"]
    }
}


def setup_logging(default_path=CURRENT_LOGGING_CONFIGURATION, default_level=logging.DEBUG, env_key=ENV_VAR_LOGGING):

    if not os.path.exists(LOGS_DIRECTORY):
        os.mkdir(LOGS_DIRECTORY)
    if not os.path.exists(TMP_DIRECTORY):
        os.mkdir(TMP_DIRECTORY)
    if not os.path.exists(FS_DIRECTORY):
        os.mkdir(FS_DIRECTORY)

    path  = default_path
    if (path == None):
        path = CURRENT_LOGGING_CONFIGURATION
    value = os.getenv(env_key, None)
    if value:
        path = value
    if os.path.exists(path):
        with open(path, 'rt') as f:
            log_config = json.load(f)
        logging.config.dictConfig(log_config)
        saveDataFile(default_logging_config, DEFAULT_LOGGING_CONFIGURATION)
        logger.info("Sample  Configuration Saved in : " + DEFAULT_LOGGING_CONFIGURATION)
        logger.info("Logging Env. Var Cfg FileName     : ["+env_key+"="+str(value)+"]")
        logger.info("Logging Configuration Loaded from : ["+path+"]")
        logger.info("Logging Configuration : " + jsonc.dumps(log_config, indent=4))
        return log_config
    else:
        logging.basicConfig(format='%(levelname)s:%(name)s:%(message)s', level=default_level)
        logger.warning(" > NO Logging Configuration File : ["+path+"]")
        saveDataFile(default_logging_config, DEFAULT_LOGGING_CONFIGURATION)
        logger.info("Sample   Configuration Saved in : " + DEFAULT_LOGGING_CONFIGURATION)
        saveDataFile(default_logging_config, CURRENT_LOGGING_CONFIGURATION)
        logger.info("Current  Configuration Saved in : " + CURRENT_LOGGING_CONFIGURATION)
        logging.config.dictConfig(default_logging_config)
        logger.info("Default Logging Configuration : " + jsonc.dumps(default_logging_config, indent=4))
        return default_logging_config


# log_config = setup_logging(LOGGING_CONFIGURATION,default_level=logging.DEBUG,env_key="LOGGING_CONFIGURATION")

class Verbose:
    VERBOSE  = None

    @staticmethod
    def init_verbose(p_verbose: bool = False):
        if (Verbose.VERBOSE == None):
            Verbose.set_verbose(p_verbose, silent=True)

    @staticmethod
    def swap_verbose(silent: bool = False):
        if (Verbose.VERBOSE):
            Verbose.set_verbose(False, silent=silent)
        else:
            Verbose.set_verbose(True, silent=silent)

    @staticmethod
    def set_verbose(p_verbose: bool = True, silent: bool = False):
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)

        if (p_verbose):
            logging.basicConfig(format='%(levelname)s : %(message)s', level=logging.INFO)
            if (not silent): Term.print_yellow("Verbose ON")
            Verbose.VERBOSE = True
        else:
            logging.basicConfig(format='%(levelname)s : %(message)s', level=logging.ERROR)
            if (not silent): Term.print_yellow("Verbose OFF")
            Verbose.VERBOSE = False

logger = logging.getLogger(__name__)


###
### File Formats
###

JSON_FILE  = '.json'
JSON_FILES = ['.json', '.schema', '.desc', '.trigger' ]
YAML_FILE  = '.yaml'
YAML_FILES = ['.yaml' ]
MAKO_FILE  = '.mako'
MAKO_FILES = ['.mako', '.template' ]
PY_FILE    = '.py'
PY_FILES   = ['.py', '.rules', '.rule' ]
XML_FILE   = '.xml'
XML_FILES  = ['.xml' ]
HTML_FILE  = '.html'
HTML_FILES = ['.html' , '.htm' ]
JPG_FILE   = '.jpg'
JPG_FILES  = ['.jpg' , '.png']
CSV_FILE   = '.csv'
CSV_FILES  = ['.csv' , '.xlsx', '.xls']
ZIP_FILE   = '.zip'
ZIP_FILES  = ['.zip' , '.tar', '.tgz']

###
### Misc
###

def getHostPort():
    host = os.getenv('$AWS_ANME_NGINX', 'localhost')
    port = os.getenv('AWS_ANME_ENGINE_NGINX_PORT', '5000')
    return str(host+":"+port)


def timestamp():
    return(datetime.datetime.now().strftime("%Y_%m_%d_%H_%M_%S"))


def uuid():
    return str(uid.uuid4())


def getMainScript():
    return get_nakedname(sys.argv[0])


def open_browser(url):
    logger.info("Opening Browser on ULF : "+str(url))
    webbrowser.open(url)

###
### Term Util - Print
###

class Term:

    VERBOSE = False

    @staticmethod
    def setVerbose(verbose : bool = True):
        Term.VERBOSE = verbose

    @staticmethod
    def print_verbose(text):
        if (Term.VERBOSE):  print(colored(text, "magenta"))
        logging.debug(text)

    @staticmethod
    def print_error(text, exception : str = None):
        print(colored(text, "red"))
        logging.error(text)
        if (exception):
            print(colored(exception, "red"))
            logging.error(exception)

    @staticmethod
    def print_warning(text, exception : str = None):
        if (Term.VERBOSE):
            print(colored(text, "cyan"))
        logging.warning(text)
        if (exception):
            print(colored(exception, "red"))
            logging.warning(exception)

    @staticmethod
    def print_green(text):
        print(colored(text, "green"))
        logging.debug(text)

    @staticmethod
    def print_red(text):
        print(colored(text, "red"))
        logging.debug(text)

    @staticmethod
    def print_yellow(text):
        print(colored(text, "yellow"))
        logging.debug(text)

    @staticmethod
    def print_grey(text):
        print(colored(text, "grey"))
        logging.debug(text)

    @staticmethod
    def print_blue(text):
        print(colored(text, "blue"))
        logging.debug(text)


###
### Exec Bash
###


def runBashRule(context: dict, ruleName : str, ruleContent : str, ruleType : str) -> dict:

    lId = uuid()
    outfile  = TMP_DIRECTORY+os.sep+lId+"_outpjson"
    infile   = TMP_DIRECTORY+os.sep+lId+"_inpjson"
    ruleType = ruleType       # get_extension(ruleFile)
    ruleName = ruleName       # get_basename(ruleFile)
    ruleDir  = TMP_DIRECTORY  # get_directory(ruleFile)
    ruleFile = ruleDir+os.sep+lId+"_"+ruleName+"."+ruleType
    saveDataFile(context, infile)
    saveFileContent(ruleContent, ruleFile)

    bachPath    = CONFIG_DIRECTORY
    bashCommand = bachPath+os.sep+"rule.sh -s -output="+outfile+" -input="+infile+" -rule="+ruleFile+" -type="+ruleType

    logger.info("runBash command : \n"  + str(bashCommand))
    logger.info("runBash context input : \n"  + to_json(context, 4))

    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()

    outJSON = loadDataFile(outfile)
    logger.info("runBash stderr error  : \n"  + str(error))
    logger.info("runBash stdout output : \n"  + str(output))
    logger.info("runBash context output : \n"  + to_json(outJSON, 4))

    safeFileRemove(outfile)
    safeFileRemove(infile)
    safeFileRemove(ruleFile)
    return outJSON

###
### Statistics
###

OperationsStats    = None  # pd.DataFrame(columns=('TimeStamp', 'Latency', 'Operation', 'Request', 'Response', 'ResponseCode'))
Max_Last_Operation = 100
Last_Operations    = deque(Max_Last_Operation*[object], Max_Last_Operation)


class Operation():

    def __init__(self, operation : str = None, request : str = None):
        self.start(operation, request)
        self.timestamp = datetime.datetime.now()
        self.operation = None
        self.request   = None
        self.response  = None
        self.responseCode = None
        self.latency   = None

    def start(self, operation: str = None, request: str = None):
        # current date and time
        self.timestamp = datetime.datetime.now()
        self.operation = operation
        self.request   = request

    def completed(self, response: str = None, responseCode = 200):
        self.response     = response
        self.responseCode = responseCode
        diff = datetime.datetime.now() - self.timestamp
        self.latency = round(diff.seconds * 1000 + diff.microseconds / 1000, 0)
        Last_Operations.appendleft(cast(self, object))
        global OperationsStats
        OperationsStats = OperationsStats.append(
                                   {   'TimeStamp':    self.timestamp,
                                       'Latency':      self.latency,
                                       'Operation':    self.operation,
                                       'Request':      self.request,
                                       'Response':     self.response,
                                       'ResponseCode': self.responseCode
                                   }, ignore_index=True)

    def __txt__(self) -> str:
        text = " " + str(self.operation) + " " + str(self.responseCode)+" : " + str(self.latency) + " - " + str(self.request)
        return text

    @staticmethod
    def last_operations() -> str:
        text = ""
        text = text + "\nStats : \n"+str(OperationsStats.describe())  # exclude=["ResponseCode"]))
        for op in Last_Operations:
            text = (text + "\n" + op.__txt__()) if (op) else ""
        text = text + "\nStats : \n"+str(OperationsStats.describe())  # exclude=["ResponseCode"]))
        return text


###
### Rest Query
###

# HTTP REST Method
# GET    http://[hostname]/tasks/all           Retrieve list of tasks
# GET    http://[hostname]/tasks/[task_id]     Retrieve a task
# POST   http://[hostname]/tasks/[task_id]     Create a new task
# PUT    http://[hostname]/tasks/[task_id]     Update an existing task
# DELETE http://[hostname]/tasks/[task_id]     Delete a task
# PATCH  http://[hostname]/tasks/[task_id]     Execute a task


VERB_LIST   = ["list", "listall", "all"]
VERB_GET    = ["get", "view", "-get-"]
VERB_SAVE   = ["save", "create", "update", "put", "patch", "post", "-create-", "-update-"]
VERB_DELETE = ["delete", "remove", "del", "rm", "-delete-"]


class Query:

    def __init__(self, op: str, request, endpoint: str, payload: str = None, classname: str = None):
        self.logger    = rslogger
        self.op        = op
        self.classname = classname  # Caller Class
        self.request   = request
        self.endpoint  = endpoint
        self.elemName  = "None"
        self.qall      = dict()     # All Parameters
        self._data     = None
        if isinstance(request, str):  # For Testing
            self.operation = Operation(op, request)
            self.payload   = payload    # request.json
            self.url       = request    # request.url
            self.server    = urlparse(unquote(request)).netloc
        else:                                   # From Flask
            self.operation = Operation(op, unquote(request.url))
            self.payload   = request.json         # request.json
            self.url       = request.url          # request.url
            self.server    = urlparse(unquote(request.url)).netloc

        self.query    = unquote((re.sub("^htt.*://.*:[0-9]*/", "", self.url)))   # Query String     route/id/sub/verb;p=v?param=value
        self.query    = unquote((re.sub("^htt.*://[^/]*/", "", self.url)))   # Query String     route/id/sub/verb;p=v?param=value
        self.loc      = unquote(self.url).replace(self.query, "")                # Location String: http://host:port/

        self.parsed_url  = urlparse(unquote(self.url))
        # scheme / netloc / path / params / query / fragment / username / password / hostname / port

        # Path Parameters / Variables Extraction
        # EndPoint: /route/<string:StoreName>/<string:FileName>
        # Path:     /route/ActualStoreName/ActualFileName/
        # => Path Parameter: StoreName = ActualStoreName
        # => Path Parameter: FileName  = ActualFileName
        endPointPath = endpoint
        self.pathParams = dict()
        lastQuery = re.sub("^[^/]*/", "", self.query)
        lastQuery = re.sub("\?.*$", "", lastQuery)# Query String     route/id/sub/
        match = re.search("<([a-zA-Z0-9_:]*)>", endPointPath)
        while match:
            if (lastQuery == ""): break
            arg_name  = re.sub(".*:", "", match.groups()[0])
            if isinstance(request, str):
                arg_value = re.sub("^[^/]*/", "", lastQuery)
                lastQuery = re.sub(arg_value, "", lastQuery)
            else:
                arg_value = request.view_args[arg_name]  # Extract Param From Path
            if (arg_name): self.elemName = arg_name
            self.pathParams[arg_name] = arg_value
            self.addParam(arg_name, arg_value)
            endPointPath = endPointPath.replace("/" + match.group(0), "")
            match = re.search("<([a-zA-Z0-9_:]*)>", endPointPath)
        self.endPointPath = endPointPath

        # Verb Extraction from Path Params : Param without a value
        # "CTT3=CTT3&verb&CTT=CTT&CTT2=CTT2?TT=TT"
        # "CTT3=CTT3&Function=verb&CTT=CTT&CTT2=CTT2?TT=TT"
        path = self.parsed_url.params
        match = re.search("([\%a-zA-Z0-9_:\-'\.\[\]]*=[\%a-zA-Z0-9_:\-'\.\[\]]+).", path)
        while match:
            path = path.replace(match.group(0), "")
            match = re.search("([\%a-zA-Z0-9_:\-'\.\[\]]*=[\%a-zA-Z0-9_:\-'\.\[\]]+)", path)
        self.verb = re.sub("'", "", re.sub("=", "", re.sub("\&*", "", unquote(path))))

        # Verb Extraction: from Query Params : Param Param without a value
        # "TT3=CTT3?verb&CTT=CTT&CTT2=CTT2&TT=TT"
        # "TT3=CTT3?Function=verb&CTT=CTT&CTT2=CTT2&TT=TT"
        if ((self.verb == None) or (self.verb == "")):
            path = self.parsed_url.query
            match = re.search("([\%a-zA-Z0-9_:\-'\.\[\]]*=[\%a-zA-Z0-9_:\-'\.\[\]\/]+)", path)
            while match:
                path = path.replace(match.group(0), "")
                match = re.search("([\%a-zA-Z0-9_:\-'\.\[\]]*=[\%a-zA-Z0-9_:\-'\.\[\]\/]+)", path)
        self.verb = re.sub("'", "", re.sub("=", "", re.sub("\&*", "", unquote(path))))

        # /v1/endpoint                -> List Stores
        # /v1/endpoint/<store>        -> Get List Files
        # /v1/endpoint/<store>/<file> -> Get One File
        # /v1/enrichers               -> List Enrichers
        # /v1/enrichers/<enricher>    -> Get Enricher

        # GET/PUT/POST/DELETE => File Operations
        # PATCH: Special Operations + Backup
        # OPTIONS: Help
        self.query        = unquote(self.parsed_url.query)
        self.path         = self.parsed_url.path
        self.qp           = parse_qs(self.parsed_url.params)  # Path  Parameters / Variables
        self.qs           = parse_qs(self.parsed_url.query)   # Query Parameters
        self.qall         = { **self.qall, **self.qs}
        self.qall         = { **self.qall, **self.qp}        # All Parameters
        if (self.hasParam("function")):
            self.verb = self.getParam("function")
        if (self.hasParam("verb")):
            self.verb = self.getParam("verb")
        if (self.hasParam("action")):
            self.verb = self.getParam("action")
        if (self.hasParam("task")):
            self.verb = self.getParam("task")
        if (self.payload != None):
            self.qall    = self.qall  # {**self.payload, **self.qall}
        if ((self.verb == None) or (self.verb == "")):
            if ((self.op.upper() == "GET")):    # No Verb = List All
                if (self.getNPathParam() == 0):
                    self.verb = "-all-"
                else:
                    self.verb = "-get-"
            if (self.op.upper() == "PUT"):      # No Verb = update
                self.verb = "-update-"
            if (self.op.upper() == "POST"):     # No Verb = create
                self.verb = "-create-"
            if (self.op.upper() == "PATCH"):    # No Verb = backup
                self.verb = "-backup-"
            if (self.op.upper() == "OPTIONS"):  # No Verb = help
                self.verb = "-options-"
            if (self.op.upper() == "DELETE"):   # No Verb = backup
                self.verb = "-delete-"
        self.logger.info("\n"
                       + "- "+self.op+": "  + self.url + "\n"
                       + "- Server     : "  + self.server + "\n"
                       + "- Operation  : "  + self.op + "\n"
                       + "- Verb       : "  + self.verb + "\n"
                       + "- Query      : "  + self.query + "\n"
                       + "- Endpoint   : "  + self.endPointPath + "\n"
                       + "- Element    : "  + str(self.elemName) + "\n"
                       + "- Path Par.  : "  + str(self.pathParams) + "\n"
                       + "- LPath Par. : "  + str(self.qp) + "\n"
                       + "- QS Par.    : "  + str(self.qs) + "\n"
                       + "> Payload    : "  + str(self.payload) + "\n"
                       + "> Content    :\n" + str(self.getAsContent()) + "\n")

    def buildURL(self, verb, endpoint_params: list = None, query_param: list = None):
        if isinstance(self.request, str) : return "https://amne.com/TestURL/"+verb
        # url_style = "Path"
        # buildURL("create", [('EP1', 'EV1'), ('EP2', 'EP2')], [('QP1', 'QV1'), ('QP2', 'QV2')])
        # => http://host:port/fs/EP1/EP2?create?QP1=QV1&QP2=QV2
        # url_style = "Query"
        # buildURL("create", [('EP1', 'EV1'), ('EP2', 'EP2')], [('QP1', 'QV1'), ('QP2', 'QV2')])
        # => http://host:port/fs/create?EP1=EV1&EP2=EP2?QP1=QV1&QP2=QV2
        url = self.loc+re.sub("^/", "", self.endPointPath)
        if (endpoint_params):
            for i , n in enumerate(endpoint_params) :
                if (n[1]) in self.endpoint:  continue
                if (i == 0): url = url + "/" + n[1]
                else:        url = url + "/" + n[1]
        if (query_param):
            url = url + "?"
            if (verb != None) and (verb != ""): url = url + verb
            for i , n in enumerate(query_param) :
                if (i == 0): url = url + "&" + n[0] + "=" + n[1]
                else:        url = url + "&" + n[0] + "=" + n[1]
        return url

    def formatMsg(self, message, store: str = None, file: str = None, operation: str = None, tag: str = None, code=0, json=True):
        if (json) :
            msg = SuperDict()
            msg.set("Request",  self.op)
            msg.set("URL",      self.url)
            if (code > 299)        : msg.set("Status",    "ERROR")
            if (code < 300)        : msg.set("Status",    "OK")
            if (code != 0)         : msg.set("Code",      str(code))
            if (code > 299)        : msg.set("Help",      self.buildURL("help"))
            if (store != None)     : msg.set("Store",     str(store))
            if (file != None)      : msg.set("File",      str(file))
            if (operation != None) : msg.set("Operation", str(operation))
            if (self.verb != None) : msg.set("Action",    str(self.verb))
            if (tag != None)       : msg.set("Tag",       str(tag))
            if (message != None)   : msg.set("Message",   str(message))
            return msg.getAsData()
        else :  # Text
            txt = ""
            if (code != 0)         : txt = txt + "\n Code = ["+str(code)+"]"
            if (store != None)     : txt = txt + "\n Store = ["+store+"]"
            if (file != None)      : txt = txt + "\n File = ["+file+"]"
            if (operation != None) : txt = txt + "\n Operation = ["+operation+"]"
            if (tag != None)       : txt = txt + "\n Tag = ["+tag+"]"
            txt = "[" + self.op+" : "+self.getVerb()+"] > " + txt + " : \n" + str(message)
            if (code > 299):
                txt = txt + "\n\nHelp: " + self.buildURL("help")
            return txt

    def success(self, data, code=200, store : str = None, file : str = None, operation : str = None, tag : str = None):
        if (isinstance(data, dict)):
            return self.response(data, code)
        elif (isinstance(data, str)):
            return self.response(self.formatMsg(data, store, file, operation, tag, code), code=code)
        else:
            return self.response(self.formatMsg(str(data), store, file, operation, tag, code), code=code)

    def response(self, data, code=200, pException=None, json=True):
        if (pException != None):
            rslogger.exception("Exception Stack Trace : "+str(pException))
            try:
                exceptionText = str(pException.args[0])
            except:
                exceptionText = ""
            if (isinstance(data, SuperDict)):
                data.set("Error", pException.__class__.__name__ + " : " + exceptionText)
            if (not isinstance(data, str)):
                exceptionText = str(data)
            else:
                exceptionText = data + "\n -> " + pException.__class__.__name__ + " : " + exceptionText
            rslogger.info("REST Response : RC = " + str(code) + " \n" + exceptionText)
            self.operation.completed(str(data), code)
            if (isinstance(data, SuperDict)):
                data = data.getAsData()
            return data, code
            # return str(exceptionText), code

        rslogger.info("REST Response : RC = " + str(code) + " \n" + str(data))
        self.operation.completed(str(data), code)
        if isinstance(data, str):
            return data, code
        elif isinstance(data, SuperDict):
            return data.getAsData(), code
        elif isinstance(data, dict):
            return data, code
        else:
            return str(data), code

        """
        200: "OK."
        201: "OK - Created."
        202: "OK - Accepted."
        204: "OK - No Content."
        400: "OK - Unspecified Error."
        401: "OK - Not authorized."
        403: "OK - Forbidden."
        404: "OK - Not Found."
        405: "OK - Not Allowed."
        501: "OK - Not Supported."
        """

    def error(self, message : str = "Error", code=400, store : str = None, file : str = None, operation : str = None, tag : str = None):
        self.operation.completed(file, code)
        return self.response(self.formatMsg(message, store, file, operation, tag, code), code)

    def notFound(self, message : str = "Not Found", code=404 , store : str = None, file : str = None, operation : str = None, tag : str = None):
        self.operation.completed(file, code)
        return self.response(self.formatMsg(message, store, file, operation, tag, code), code)

    def notAllowed(self, message : str = "Not Allowed", code=405 , store : str = None, file : str = None, operation : str = None, tag : str = None):
        self.operation.completed(file, code)
        return self.response(self.formatMsg(message, store, file, operation, tag, code), code)

    def notSupported(self, message : str = "Not Supported", code=501, store : str = None, file : str = None, operation : str = None, tag : str = None):
        self.operation.completed(file, code)
        return self.response(self.formatMsg(message, store, file, operation, tag, code), code)

    def exception(self, message, exception : Exception = None, code=400, store : str = None, file : str = None, operation : str = None, tag : str = None):
        self.operation.completed(file, code)
        message = message + " : " + str(exception)
        return self.response(data=self.formatMsg(message, store, file, operation, tag, code), code=code, pException=exception)

    def return_data(self, data, fileName : str = "Data.txt", as_attachment=False, name : str = None):
        if (isinstance(data, SuperDict)):
            data = data.getAsData()
        if (name != None):
            data = { name : data }
        if (self.isParamTrue("Attach")):
            return self.return_text(str(data), fileName, as_attachment=as_attachment)
        else:
            return self.response(data)

    def return_message(self, content, code : int = 200):
        return str(content), code

    def return_text(self, content, fileName : str = "File.txt", as_attachment : bool = False, code : int = 200, name : str = None):
        if (self.isParamTrue("Attach")):
            as_attachment = True
        if (name != None):
            content = { name : content }
        if (isinstance(content, dict)):
            content = json.dumps(content, indent=4)
        if (isinstance(content, SuperDict)):
            content = json.dumps(content.getAsData(), indent=4)
        if (not isinstance(content, str)):
            content = str(content)
        tmp_file = TMP_DIRECTORY+os.sep+fileName
        saveFileContent(content, tmp_file)
        self.logger.info("Returned : \n"+content)
        self.operation.completed(fileName, code)
        if isinstance(self.request, str):
            return content, 200
        return send_file(
            tmp_file,
            mimetype='text/plain',
            as_attachment=as_attachment,
            attachment_filename=fileName)

    def return_file(self, fileName : str , as_attachment : bool = False, code : int = 200, name : str = None):
        self.logger.info("Returned File : "+fileName)
        if (self.isParamTrue("Attach")): as_attachment = True
        ext = get_extension(fileName)
        ext = re.sub("^\.", "", ext)
        if (ext not in ["json", "yaml", "html", "htm"]):
            ext = "plain"
        mimetype = "text/" + ext
        if (get_extension(fileName) in ["exe", "bin", "gz", "zip"]):
            mimetype = "application/octet-stream"
        if (not name): name = get_basename(fileName)
        self.operation.completed(fileName, code)
        if isinstance(self.request, str):
            return loadTextFile(fileName), 200
        return send_file(
            fileName,
            mimetype=mimetype,
            as_attachment=as_attachment,
            attachment_filename=name)

    def getParam(self, param, default=None) -> str:
        if (param in self.qall): return self.qall[param][0]
        if (param.capitalize() in self.qall): return unquote(self.qall[param.capitalize()][0])
        if (param.lower() in self.qall):      return unquote(self.qall[param.lower()][0])
        if (param.upper() in self.qall):      return unquote(self.qall[param.upper()][0])
        return default

    def getParams(self, param, default=None) -> list:
        if (param in self.qall): return self.qall[param]
        if (param.capitalize() in self.qall): return unquote(self.qall[param.capitalize()])
        if (param.lower() in self.qall):      return unquote(self.qall[param.lower()])
        if (param.upper() in self.qall):      return unquote(self.qall[param.upper()])
        return default

    def getNPathParam(self):
        return len(self.pathParams)

    def getVerb(self, default=None) -> str:
        if (self.verb != None): return self.verb
        if (default != None):    return default
        return self.op

    def hasParam(self, param):
        if (self.getParam(param) == None):
            return False
        return True

    def isPresent(self, param):
        if (self.getParam(param) == None):
            return False
        return True

    def addParam(self, name: str, value: str):
        self.appendParam(name=name, value=value)

    def appendParam(self, name: str, value: str):
        if (not (name in self.qall)) :
            self.qall[name] = list()
        self.qall[name].append(value)

    def isParamTrue(self, param, default=False) :  # Boolean
        value = ""
        if (param in self.qall): value = self.qall[param][0].lower()
        if (param.lower() in self.qall): value = self.qall[param.lower()][0].lower()
        if (param.upper() in self.qall): value = self.qall[param.upper()][0].lower()
        if (value == None):    return default
        if value in ['1' , 'true' , 'yes', 'ok', 'oui', 'vrai', 'si', 'da', 'pajalousta'] :
            return True
        if value in ['0' , 'false' , 'no', 'none', 'non', 'faux', "net", "niet", "not"] :
            return False
        return default

    def getRoute(self) -> str:
        return self.route

    def restOperation(self, op: str):  # Boolean
        if (self.op.lower() == op.lower()) : return True
        return False

    def checkOperation(self, restOp: str, refuse = True) -> str:
        if (self.restOperation(restOp)) :
            return restOp.upper()
        else:
            if (refuse): raise NameError("REST Operation Not Supported : ["+self.op+"] for ["+self.getVerb()+"]")
            return ""

    def operationIn(self, plist):
        return self.getVerb().lower() in plist

    def matchOperation(self, restOperation, queryVerb : list = None):
        if isinstance(restOperation, str):
            if (self.op.upper() != restOperation.upper()):
                return False
            if (queryVerb == None):
                return True
            if self.getVerb().lower() in queryVerb :
                return True
            for qv in queryVerb:
                if self.isParamTrue(qv, False):
                    return True
            return False
        else:
            for op in restOperation:
                if self.matchOperation(op, queryVerb):
                    return True
            return False

    def isHelp(self):
        if (self.op.upper() in [ "OPTIONS"]):
            return True
        return self.operationIn(["help", "man", "SOS", "Aide", "Mayday", "Aiuto"])

    def isBackUp(self):
        return self.matchOperation("PATCH", ["backup"])

    def isFileOperation(self):
        if (self.op.upper() in [ "PUT", "POST", "DELETE"]):
            return True
        if (self.op.upper() in [ "GET"]):
            if (self.operationIn(["-all-", "all", "allnames",
                                  "-get-", "get",
                                  "-list-", "list", "listall", "listfiles", "files", "liststores", "stores",
                                  "-backup-", "backup", "bup",
                                  "-delete-", "delete", "del", "remove", "rem",
                                  "-create-", "create", "new", "save",
                                  "-update-", "update", "up", "change",
                                  "data",  "content", "file", "text",
                                  "push",  "prod",
                                  "desc",  "descriptor",
                                  "repos", "repository",
                                  "vc",    "versioncontrol",
                                  "sch",   "schema"])):
                return True
        if (self.op.upper() in [ "PATCH"]):
            if (self.operationIn(["backup", "-backup-", "back"])):
                return True
        return False

    def updateFileOperation(self, op : str = "PUT", verb : str = "-update-"):
        self.op = op
        self.verb = verb

    def setData(self):
        self._data = self.qall
        del self._data["METHOD"]
        del self._data["RESOURCE"]

    def getAsData(self):
        if (self._data != None):
            return self._data
        return loadDataContent(self.getAsContent())

    def getData(self, path : str):
        return SuperDict(self.getAsData()).get(path)

    def getParamData(self, param : str):
        if (self.hasParam(param)):
            return self.getParam(param)
        else:
            return self.getData(param)

    def getParamValues(self, param : str):
        if   (param in self.qall):              values = self.qall[param]
        elif (param.capitalize() in self.qall): values = self.qall[param.capitalize()]
        elif (param.lower() in self.qall):      values = self.qall[param.lower()]
        elif (param.upper() in self.qall):      values = self.qall[param.upper()]
        else:                                   values = self.getData(param)
        if (values == None): return list()
        if (isinstance(values, str)): values = [ values ]
        return values

    # noinspection PyBroadException
    def getAsContent(self, filename : str = "File"):
        if (self._data != None):
            return to_json(self._data)
        if (isinstance(self.request, str)):
            if (isinstance(self.payload,dict)):
                return to_json(self.payload)
            else:
                return str(self.payload)
        logger.info("getAsContent" + str(self.request.files))
        try:
            if (self.request.json != None):
                return to_json(self.request.json)
            if (self.request.data != None):
                return str(self.request.data.decode('UTF-8'))
            for filename in [ filename,
                              "File" , "FILE", "file",
                              "Content", "content", "CONTENT",
                              "Schema", "schema", "SCHEMA",
                              "Rule", "rule", "RULE",
                              "Trigger", "trigger", "TRIGGER",
                              "Ruleset", "ruleset", "RULESET", "RuleSet" 
                              "VC", "vc", "Vc",
                              "Versioncontrol", "VersionControl", "versioncontrol", "VERSIONCONTROL" 
                              "Py", "py", "PY",
                              "Mako", "mako", "MAKO",
                              "Template", "template", "TEMPLATE",
                              "Data", "data", "DATA",
                              "Yaml", "yaml", "YAML",
                              "Json", "json", "JSON" ]:
                if filename in self.request.files:
                    f = self.request.files[filename]
                    fn = secure_filename(f.filename)
                    content = loadFileContent(fn)
                    return content
                elif filename in self.request.form:
                    return self.request.form[filename]
                    # return data
        except:
            return None
        return None


# noinspection PyBroadException
class Request:

    def __init__(self, server):
        self.server        = server
        self.rest_request  = ""
        self.op            = "GET"
        self.rest_response = ""
        self.r_code  = 0
        self.s_data  = None  # Send Dict
        self.s_text  = None  # Send Dict
        self.r_data  = None  # Returned JSON / Dict
        self.r_text  = None  # Returned Text
        self.d_data  = None  # Returned SuperDict
        self.logs    = ""    # Logs so far
        self.timestamp = datetime.datetime.now()
        self.latency = 0

    def start(self):
        self.timestamp = datetime.datetime.now()

    def completed(self):
        diff = datetime.datetime.now() - self.timestamp
        self.latency = round(diff.seconds * 1000 + diff.microseconds / 1000, 0)
        self.logs = self.logs + self.txt()
        logger.info(self.txt())

    def handle(self, request : str, op : str = None, data=None, headers = None):
        self.start()
        current_op = self.op
        if (op != None) : current_op = op
        self.op = current_op
        if (not (current_op in ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"] )):
            self.r_text = "Invalid REST Operation : "+current_op
            self.r_code = 400
            self.completed()
            return None
        if ((self.server.startswith("http:")) or (self.server.startswith("https:"))):
            self.rest_request = self.server + '/' + request
        else:
            self.rest_request = ANME_HTTP + "://" + self.server + '/' + request
        #  rslogger.info("REST "+op+" : " + self.rest_request)
        self.s_data = None
        self.s_text = None
        self.r_data = None
        self.d_data = None
        self.r_text = None
        if (data != None):
            if (isinstance(data, dict)):      self.s_data = data
            if (isinstance(data, SuperDict)): self.s_data = data.getAsData()
            if (isinstance(data, str)):       self.s_text = data
        if (self.s_data):
            self.s_text = json.dumps(self.s_data)
        try:
            if (self.s_data):
                if (current_op == "GET")    : self.rest_response = requests.get(self.rest_request,     json=self.s_data, headers=headers, verify=False)
                if (current_op == "DELETE") : self.rest_response = requests.delete(self.rest_request,  json=self.s_data, headers=headers, verify=False)
                if (current_op == "OPTIONS"): self.rest_response = requests.options(self.rest_request, json=self.s_data, headers=headers, verify=False)
                if (current_op == "POST")   : self.rest_response = requests.post(self.rest_request,    json=self.s_data, headers=headers, verify=False)
                if (current_op == "PUT")    : self.rest_response = requests.put(self.rest_request,     json=self.s_data, headers=headers, verify=False)
                if (current_op == "PATCH")  : self.rest_response = requests.patch(self.rest_request,   json=self.s_data, headers=headers, verify=False)
            else:
                if (current_op == "GET")    : self.rest_response = requests.get(self.rest_request,     data=self.s_text, headers=headers, verify=False)
                if (current_op == "DELETE") : self.rest_response = requests.delete(self.rest_request,  data=self.s_text, headers=headers, verify=False)
                if (current_op == "OPTIONS"): self.rest_response = requests.options(self.rest_request, data=self.s_text, headers=headers, verify=False)
                if (current_op == "POST")   : self.rest_response = requests.post(self.rest_request,    data=self.s_text, headers=headers, verify=False)
                if (current_op == "PUT")    : self.rest_response = requests.put(self.rest_request,     data=self.s_text, headers=headers, verify=False)
                if (current_op == "PATCH")  : self.rest_response = requests.patch(self.rest_request,   data=self.s_text, headers=headers, verify=False)
        except Exception as ex:
            logger.exception("Exception REST Operation : "+current_op)
            self.r_code = 400
            self.r_text = str(ex).replace("\\n", "\n")
            self.completed()
            return None
        self.r_code   = self.rest_response.status_code
        self.r_text   = self.rest_response.text.replace("\\n", "\n")
        try:
            self.r_data   = checkJsonContent(self.r_text)
            if (isinstance(self.r_data, dict)):
                self.d_data   = SuperDict(self.r_data)
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
        txt = "\n> "+self.op + " " + self.rest_request+"\n"
        if (self.s_text):
            txt = txt + "> "+str(self.op)+"\n" + str(self.s_text) + "\n"
        if (self.isError()):
            txt = txt + "< Error : " + str(self.r_code) + " (" + str(self.latency) + ")\n"
        elif (self.r_text):
            txt = txt + "< OK : "    + str(self.r_code) + " (" + str(self.latency) + ")\n" + textToJson(self.r_text) + "\n"
        return txt+"---"

    def summary(self):
        return "(" + str(self.latency)+") " + str(self.r_code) + " - " + self.op + " " + self.rest_request

    def getURL(self):
        return self.rest_request

    def isError(self):
        return self.r_code > 299

    def raiseError(self):
        if (self.r_code > 299):
            raise LookupError(self.r_text)

    def getError(self):
        return self.r_text

    def getContent(self):
        return self.r_text

    def getSuperDict(self):
        return self.d_data

    def getData(self): return self.r_data

    def get(self, request: str, data=None): return self.handle(request, "GET", data)

    def post(self, request: str, data=None): return self.handle(request, "POST", data)

    def put(self, request: str, data=None): return self.handle(request, "PUT", data)

    def delete(self, request: str, data=None): return self.handle(request, "DELETE", data)

    def patch(self, request: str, data=None): return self.handle(request, "PATCH", data)

    def options(self, request: str, data=None): return self.handle(request, "OPTIONS", data)


class RestServer():

    help_text = '''
## API_TARGET_T Operations

Rest Query : https://[server:port]/API_TARGET?<operation>&Param=Value"

## Help                GET     API_TARGET?help

'''

    def __init__(self, api_target: str):
        self.api_target = api_target
        logger.info("Starting "+self.__class__.__name__+" - API Target : [" + api_target + "]")

    def processQuery(self, q: Query):
        logger.info(q.op+" : "+q.url)
        return self.process(q)

    def getHelp(self):
        help_text = RestServer.help_text
        help_text = help_text.replace("API_TARGET_T", self.api_target.title()).replace("API_TARGET", self.api_target)
        help_text = help_text.replace("STORE_NAME", self.fs_name)
        return help_text

    @staticmethod
    def getEndPoint(SERVER_API_TARGET: str, RESOURCE_API_TARGET: str, endingPath: str = None):
        if (SERVER_API_TARGET == None) or (SERVER_API_TARGET == ""):
            return "/" + RESOURCE_API_TARGET
        else:
            return "/" + SERVER_API_TARGET + "/" + RESOURCE_API_TARGET


class FileRestServer(RestServer):

    help_text = '''
## API_TARGET_T Operations
#> StoreName=STORE_NAME

Rest Query : https://[server:port]/API_TARGET?<operation>&Param=Value { Payload }

## Help                GET     API_TARGET?help

#> All FileStore Operations with StoreName=STORE_NAME and FileName=<FILE_NAME>

'''

    def __init__(self, api_target: str, file_store, file_store_rs, elem_name = None):
        super().__init__(api_target)  # Default: "templates"
        self.fs           = file_store
        self.fs_name      = self.fs.getStoreName()
        self.fsRestServer = file_store_rs
        if (elem_name == None) : elem_name = re.sub("s$", "",  api_target.title())+"Name"
        self.elem_name    = elem_name
        logger.info("Starting " + self.__class__.__name__ + " : " +
                    " - API Target : [" + self.api_target + "] " +
                    " - FileStore  : [" + self.fs_name + "]" +
                    " - Elements   : [" + str(self.elem_name) + "] " )

    def getHelp(self, elemName = None):
        if (elemName):
            help_text = self.fsRestServer.getHelp(elemName != None)
            return help_text.replace("API_TARGET", self.api_target).replace("filestore", self.api_target).replace("/<StoreName>", "").replace("FileName", elemName)
        else:
            help_text = FileRestServer.help_text + self.fsRestServer.getHelp(elemName != None)
            help_text = help_text.replace("API_TARGET_T", self.api_target.title()).replace("API_TARGET", self.api_target)
            help_text = help_text.replace("STORE_NAME", self.fs_name)
            return help_text

    def checkFileStoreElement(self, q: Query, elementName: str, fs  , ifExist = True, okIfAbsent = False) -> str:
        # Make sure all elementName, FileName and StoreName are indicated
        q.appendParam("StoreName", fs.getStoreName())
        if q.hasParam(elementName):
            q.appendParam("FileName", q.getParam(elementName))
        elif q.hasParam("FileName"):
            q.appendParam(elementName, q.getParam("FileName"))
        elif q.hasParam("Name"):
            q.appendParam("FileName", q.getParam("Name"))
            q.appendParam(elementName, q.getParam("Name"))
        file  = q.getParam(elementName)
        if (file == None):
            file = q.getParam("FileName")
        if (file == None):
            file = q.getParam("Name")
        q.appendParam("FileName", file)
        q.appendParam(elementName, file)
        if (file == None) and (not okIfAbsent):
            raise NameError(elementName+" Not Indicated : &"+elementName+"=["+elementName+"]")
        if (ifExist) and (not self.fs.existFile(file)):
            if (not self.fs.existFile(file)): raise NameError(elementName+" not found : ["+file+"] in Store : ["+fs.getStoreName()+"]")
        return file


class RestResource():

    def __init__(self, resource_name: str, endpoint: str, rest_server: RestServer, help_text: str, short_help: str, swagger: str):
        self.endpoint      = endpoint
        self.help_text     = help_text
        self.short_help    = short_help
        self.swagger       = swagger
        self.rs            = rest_server
        self.resource_name = resource_name

    def getEndPoint(self):
        return self.endpoint

    def getResourceName(self):
        return self.resource_name

    def getHelpText(self, server_address="server:port"):
        if (self.help_text == None) or (self.help_text == ""): return None
        return self.help_text.replace("API_TARGET", self.endpoint).replace("server:port", server_address).replace("string:", "")

    def getShortHelp(self, server_address="server:port"):
        if (self.short_help == None) or (self.short_help == ""): return None
        return "> HELP "+self.short_help+" - " + ANME_HTTP + "://"+str(server_address)+"/"+str(self.resource_name)+"?help"

    def getSwagger(self):
        return self.swagger

    def getRestServer(self):
        return self.rs


class RestServersRepository():

    # Static
    _resources = dict()

    @staticmethod
    def add_resource(descriptor : RestResource):
        RestServersRepository._resources[descriptor.resource_name] = descriptor

    @staticmethod
    def get_resource(resource_name: str):
        for key in RestServersRepository._resources.keys() :
            if (RestServersRepository._resources[key].resource_name.lower() == resource_name.lower()):
                return RestServersRepository._resources[key]

    @staticmethod
    def getShortHelp(resource_name: str = None):
        full_help_text = ""
        if (resource_name == None) or (resource_name == "all") or (resource_name == ""):
            for key in RestServersRepository._resources.keys() :
                res_help = RestServersRepository._resources[key].getShortHelp()
                if (res_help == None): continue
                full_help_text = full_help_text + "\n" + res_help
            return full_help_text
        else:
            for key in RestServersRepository._resources.keys():
                if resource_name.lower() in key.lower():
                    res_help = RestServersRepository._resources[key].getShortHelp()
                    if (res_help == None): continue
                    full_help_text = full_help_text + "\n" + res_help
            if (full_help_text != ""):
                return full_help_text
        return RestServersRepository.getShortHelp()

    @staticmethod
    def getHelpText(resource_name: str = None):
        full_help_text = ""
        if (resource_name == None) or (resource_name == "all") or (resource_name == ""):
            for key in RestServersRepository._resources.keys() :
                res_help = RestServersRepository._resources[key].getHelpText()
                if (res_help == None): continue
                full_help_text = full_help_text + "\n" + res_help
            return full_help_text
        else:
            for key in RestServersRepository._resources.keys() :
                if resource_name.lower() in key.lower():
                    res_help = RestServersRepository._resources[key].getHelpText()
                    if (res_help == None): continue
                    full_help_text = full_help_text + "\n" + res_help
            if (full_help_text != ""):
                return full_help_text
        return RestServersRepository.getHelpText()

    @staticmethod
    def call(name, frame, request):
        args, _, _, values = inspect.getargvalues(frame)
        method = inspect.getframeinfo(frame)[2].upper()
        params = ""
        for i in args:
            if (i == "self") : continue
            params = params+" - %s = %s" % (i, values[i])
        res = RestServersRepository.get_resource(name)
        logger.info(method + " : " + name + params + " - " + request.url)
        return res.rs.processQuery(Query(method, request, endpoint=res.endpoint, classname=name))

    @staticmethod
    def callByResource(resourceName: str, method: str, q: Query):
        res = RestServersRepository.get_resource(resourceName)
        logger.info(method + " : " + resourceName + " - " + q.request.url)
        return res.rs.processQuery(q)

###
### Channels
###


class Channel():

    def __init__(self, name):
        self.name   = name
        self.config = dict()

    def getConfig(self) -> dict:
        return self.config

    def getName(self) -> str:
        return self.__class__.__name__

    @staticmethod
    def sendMessage(dc):
        pass

###
### Obfuscating Codec
###


def obfuscate_enc(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()


def obfuscate_dec(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

###
### Version Control Support
###


def rreplace(s, old, new, occurrence):
    # rreplace - How to replace the last occurrence of an expression in a string?
    li = s.rsplit(old, occurrence)
    return new.join(li)

def find_between(content, start, end):
    found = re.search(start + '([\s\S]*?)'+end, content)
    if (found == None): return None
    found = found.group(1)
    found = re.sub(start, "", found)
    found = re.sub(end, "", found)
    return found


def remove_between(content, start, end):
    found = re.sub(start+'([\s\S]*?)'+end, "", content)
    return found


def replace_between(originalText, delimiterA, delimiterB, replacementText):
    leadingText = originalText.split(delimiterA)[0]
    if (leadingText == originalText): return originalText
    if (len(originalText.split(delimiterB)) == 1): return originalText
    trailingText = originalText.split(delimiterB)[1]
    if (trailingText == originalText): return originalText
    return leadingText + delimiterA + replacementText + delimiterB + trailingText


def multiple_replace(theDict, theText):
    #  Create a regular expression  from the dictionary keys
    regex = re.compile(r'(%s)' % "|".join(theDict.keys()))
    return regex.sub(lambda mo: theDict[
        [ k for k in theDict if
            re.search(k, mo.string[mo.start():mo.end()])
        ][0]], theText)


def multiple_remove(theList, theText):
    lDict = dict()
    for listItem in theList: lDict[listItem] = ""
    return multiple_replace(lDict, theText)

'''
l = ( 'ba[rz]*' , '<'  )
d = { 'ba[rz]*' : 'bar', '<' : '[' }
s = 'barzzzzzz i <'
print (multiple_replace(d, s))
print (multiple_remove(l, s))
bar i [
 i 
TT/TT/TT
TT/TT/TT
'''

###
### Format Convertor
###


def insert_tuple(t, offset, value):
    lst = list(t)
    lst.insert(offset, value)
    return tuple(lst)


def json_encode_multiline(text: str):
    if (text == None): return ""
    return p.quote(text)


def json_decode_multiline(text: str):
    return p.unquote(text)


def to_yaml(obj,  indent=4):
    return(yaml.safe_dump(obj,  indent=indent, default_flow_style=False))


def to_json(obj,  indent=4):
    return(jsonc.dumps(obj,  indent=indent))


def to_str(data):
    return(str(data))


def to_None(data):
    if (not data) : return "None"
    if (data == "null") : return "None"
    return(str(data))


def listToJson(text, value = "Missing") -> str:
    the_list = text.strip('[]\n"').replace('"', '').replace(' ', '').replace('\'', '').split(',')
    the_dict = dict()
    for elem in the_list:
        if (elem == ""): continue
        the_dict[elem] = str(value)
    the_text = json.dumps(the_dict, indent=4)
    return the_text


def textToJson(text, indent=4) -> str:
    try:
        the_dict = json.loads(text)
    except:
        return text
    the_text = json.dumps(the_dict, indent=indent)
    return the_text


def textToList(text) -> list:
    if (not text) : return list()
    return text.strip().strip('[]\n"').replace('"', '').replace(' ', '').replace('\'', '').split(',')


def isListContainedInList(subList : list, fullList : list) -> bool:
    return set(subList).issubset(fullList)


def checkJson(text) -> bool:
    if (text == None): return True
    text = text.strip()
    if (text == ""):  return True
    try:
        the_dict = json.loads(text)
        if (the_dict): return True
        return False
    except Exception as e:
        logger.debug(str(e))
        return False


def to_dict(obj, default=None):
    if (obj == None):
        return default
    if (isinstance(obj, dict)):
        return obj
    if (isinstance(obj, SuperDict)):
        return obj.getAsData()
    if (isinstance(obj, str)):
        return loadDataString(obj)
    return None


def to_list(obj, source=None, default=None):
    if (obj == None):
        return default
    if (isinstance(obj, list)):
        return obj
    if (isinstance(obj, SuperDict)):
        return to_list.getAsData()
    if (isinstance(obj, str)):
        return [ word.strip(" \n\t\"\'") for word in obj.strip(" []{}()\n\t").split(',') ]
    if (isinstance(obj, dict)):
        lList = list()
        for key in obj.keys():
            item = obj[key]
            if (isinstance(item, dict)):
                newItem = item
            else:
                newItem = dict()
            if (source):
                newItem["__NAME__"] = key
                newItem["__DESCRIPTION__"] = key
                newItem["__SOURCE__"] = str(source)
            lList.append(newItem)
        return lList
    return None

###
### Loading File in Various Format
###


def loadDataFile(fileName: str) -> dict:
    try:
        fName = fileName
        # If without extension, test which extension exists : '.json' or ".yaml"
        for theFileName in [fileName, fileName + ".json", fileName + ".yaml"]:
            if os.path.isfile(theFileName):
                fName = theFileName
                break
        logger.debug("Reading File : " + fName)
        # Find out Extension & Load
        file_ext = get_extension(fName).lower()
        if file_ext in JSON_FILES:
            return loadJsonFile(fName)
        if file_ext in YAML_FILES:
            return loadYamlFile(fName)
        else:
            logger.info("Not a JSON or YAML File : " + theFileName)
            raise NameError("File Format/Extension not supported : "+file_ext+" for file "+theFileName)
    except:
        logger.exception("Error Reading File: " + fileName)
        raise


def loadYamlFile(file_name: str) -> dict:
    try:
        with open(file_name, 'r') as yaml_stream:
            return yaml.safe_load(yaml_stream)
    except:
        logger.exception("Error Reading File : " + file_name)
        raise


def loadJsonFile(file_name: str) -> Union[dict, None]:
    try:
        if (not safeFileExist(file_name)):
            logger.error("File not Found : "+file_name)
            return None
        with open(file_name, 'r') as json_stream:
            return jsonc.load(json_stream)
    except:
        try:
            with open(file_name, 'r') as json_stream:
                return json.load(json_stream)
        except:
            logger.exception("Error Reading File : "+file_name)
            raise


def loadTextFile(file_name: str) -> str:
    return loadFileContent(file_name)


def loadDataString(content: str) -> Union[dict, None]:
    return loadDataContent(content)


# Load Data (from dict, json str, file)
def loadData(content) -> dict:
    if (content == None):
        return dict()
    if (isinstance(content, str)):
        if (safeFileExist(content)):
            return loadDataFile(content)
        else:
            to_dict(content)
    if (isinstance(content, dict)):
        return content
    if (isinstance(content, SuperDict)):
        return content.getAsData()

###
### Loading Content in Various Format
###


def checkJsonContent(content: str) -> Union[dict, None]:
    if (content == None): return None
    if (content == "")  : return None
    try:
        return jsonc.loads(content)
    except:
        try:
            return json.loads(content)
        except:
            return None


def loadFileContent(file_name: str) -> str:
    if (not safeFileExist(file_name)):
        logger.error("File not Found : " + file_name)
        return None
    with open(file_name, "r") as file:
        content = file.read()
        file.close()
    return content


def loadFileData(file_name: str, silent=False) -> Union[dict, None]:
    return loadDataContent(loadFileContent(file_name), silent)


def loadDataContent(content: str, silent=False) -> Union[dict, None]:
    if isinstance(content, dict):
        return content
    try:
        dc = loadJsonContent(content)
        # dc = loadYamlContent(content)
        if (dc == None):
            return loadYamlContent(content)
            # return loadJsonContent(content)
        else:
            return dc
    except:
        try:
            return loadYamlContent(content)
        except:
            if (not silent):
                logger.error("Error JSON or YAML Content : " + str(content)[ 0 : 50 ] + " ... ")
            return None


def loadJsonContent(content: str, silent=False) -> Union[dict, None]:
    if (content == None): return None
    if (content == "")  : return None
    try:
        return jsonc.loads(content)
    except:
        try:
            return json.loads(content)
        except:
            if (not silent):
                logger.debug("Error Loading JSON Content : " + str(content)[0 : 50] + " ... ")
            return None


def loadYamlContent(content: str, silent : bool =False) -> dict:
    try:
        parsed_data = yaml.safe_load(content)
        if not isinstance(parsed_data, dict): return None
        return parsed_data
    except:
        if (not silent):
            logger.error("Error Reading YAML Content : " + str(content)[0 : 50] + " ... ")
        return None

###
### Encryption
###


def to_bin_2_b64(bin_content : bytes) -> str:
    return base64.b64encode(bin_content).decode('ascii')


def to_b64_to_bin(b64_content: str) -> bytes:
    return base64.b64decode(b64_content.encode('ascii'))


def to_str_2_b64(str_content: str) -> str:
    return base64.b64encode(str_content.encode('utf-8')).decode('ascii')


def to_b64_to_str(b64_content: str) -> str:
    return base64.b64decode(b64_content.encode('ascii')).decode('utf-8')


def to_file_2_b64(filename) -> str:
    with open(filename, "rb") as f:
        return base64.b64encode(f.read()).decode('ascii')


def to_b64_2_file(b64_content: str, filename) -> str:
    file = open(filename, "wb")
    file.write(base64.b64decode(b64_content.encode('ascii')))
    file.close()


###
### Saving File in Various Formats
###


def saveFileContent(content, file_name: str, safe=False):
    if not os.path.exists(os.path.dirname(file_name)):
        try:
            if (os.path.dirname(file_name) != ""):
                os.makedirs(os.path.dirname(file_name))
        except OSError as exc:  # Guard against race condition
            if exc.errno != errno.EEXIST: raise
    if safe : safeUpdateFile(file_name)
    with open(file_name, "w") as file:
        content = file.write(content)
        file.close()
    return content


def saveDataFile(data, file_name: str, safe=False):
    if safe : safeUpdateFile(file_name)
    if isinstance(data, str): data = loadDataContent(data)
    try:
        logger.debug("Saving File : " + file_name)
        file_ext = get_extension(file_name).lower()
        if file_ext in JSON_FILES:
            return saveJsonFile(data, file_name)
        elif file_ext in YAML_FILES:
            return saveYamlFile(data, file_name)
        else:
            logger.info("Not a Known JSON or YAML File : " + file_name)
            raise NameError("File Format/Extension not supported : "+file_ext+" for file "+file_name)
    except:
        logger.exception("Error Writing File: " + file_name)
        raise


def saveYamlFile(data, file_name: str, safe=False):
    if safe : safeUpdateFile(file_name)
    try:
        with open(file_name, 'w') as outfile:
            outfile.write(yaml.safe_dump(data, indent=4, default_flow_style=False))
            outfile.close()
    except Exception as e:
        logger.exception("Error Writing File: " + file_name + "\n" + str(e))
        raise e


def saveJsonFile(data, file_name: str, safe=False):
    if safe : safeUpdateFile(file_name)
    try:
        with open(file_name, 'w') as outfile:
            outfile.write(jsonc.dumps(data, indent=4))
            outfile.close()
    except Exception as e1:
        try:
            with open(file_name, 'w') as outfile:
                outfile.write(json.dumps(data, indent=4))
                outfile.close()
        except Exception as e2:
            logger.exception("Error Writing File: " + file_name + "\n"+ str(e1))
            raise

###
### Safe File Management - Files Versions are Kept
###


def safeTimestamp():
    return(datetime.datetime.now().strftime("%Y_%m_%d_%H_%M_%S"))


def safeFileExist(filename):
    try:
        return os.path.exists(filename)
    except:
        return False


def safeDirExist(filename):
    try:
        return os.path.isdir(filename)
    except:
        return False


def safeCreateDir(dirname):
    # Create target directory & all intermediate directories if don't exist
    if not os.path.exists(dirname):
        os.makedirs(dirname)


def safeFileRemove(filename):
    try:
        os.remove(filename)
        return True
    except:
        logger.error("safeFileRemove Error :" + str(filename))
        return False


def safeDirectoryRemove(filename):
    return shutil.rmtree(filename, ignore_errors=True, onerror=None)


def safeDeleteFile(file_name: str, tt: str = safeTimestamp()):
    try:
        if (os.path.exists(file_name)):
            try:
                os.remove(safeDeletedFileName(file_name, tt))
            except:
                pass
            os.rename(file_name, safeDeletedFileName(file_name, tt))
            return True
        else:
            logger.error("safeDeleteFile Error - Does not exist:" + file_name)
            return False
    except:
        logger.exception("safeDeleteFile Error :"+file_name)
        return False


def safeBackupFile(file_name: str, tt: str = safeTimestamp()):
    try:
        if (os.path.exists(file_name)):
            shutil.copy(file_name, safeBackupFileName(file_name, tt))
            return True
        else:
            logger.error("safeBackupFile Error - Does not exist:" + file_name)
            return False
    except:
        logger.exception("safeBackupFile Error :"+file_name)
        return False


def safeSaveData(file_name: str, data: dict, tt: str = safeTimestamp()):
    return safeSaveFile(file_name, to_json(data), tt)


def safeSaveFile(file_name: str, content: str = None, tt: str = safeTimestamp()):
    return safeUpdateFile(file_name, content, tt)


def safeUpdateFile(file_name: str, content: str = None, tt: str = safeTimestamp()):
    try:
        path = os.path.dirname(file_name)
        if (path != ''):
            os.makedirs(path, exist_ok=True)
        if (os.path.exists(file_name)):
            shutil.copy(file_name, safeUpdatedFileName(file_name, tt))
            return True
        if (content):
            with open(file_name, "w") as file:
                file.write(content)
                file.close()
        return True
    except Exception as e:
        logger.exception("safeUpdateFile Error :"+file_name+" "+str(e))
        return False


def safeBackupFileName(file_name: str, tt: str = safeTimestamp()):
    return file_name + ".backup." + tt


def safeUpdatedFileName(file_name: str, tt: str = safeTimestamp()):
    return file_name + ".updated." + tt


def safeDeletedFileName(file_name: str, tt: str = safeTimestamp()):
    return file_name + ".deleted." + tt


def safeListFiles(pdir: str = ".", file_ext: str = "", keepExt=False) -> list:
    myList = list()
    for f in glob.glob(pdir+os.sep+"*"+file_ext):
        f = f.replace(pdir+os.sep, "")
        if (keepExt is False):
            f = remove_extension(f)
        myList.append(f)
    return myList

###
### Path Functions
###


def get_cwd_directory():
    return os.getcwd()


def get_abs_path(filename):
    return os.path.abspath(filename)


def get_tmp_directory(filename):
    tdir =  tempfile.gettempdir()
    if (filename):
        return tdir + os.sep + filename
    return tdir


def get_directory(filename):
    return os.path.dirname(filename)


def get_basename(filename):
    return os.path.basename(filename)


def get_nakedname(filename):
    return os.path.basename(filename).replace(get_extension(filename), "")


def get_strippedname(filename):
    return filename.replace(get_extension(filename), "")


def get_completename(directory: str, filename: str):
    if (os.path.dirname(filename) == ""):
        if (directory.endswith(os.path.sep)): return directory + filename
        else: return directory + os.path.sep + filename
    else:
        return filename


def get_extension(filename):
    return os.path.splitext(os.path.basename(filename))[1]


def is_ext(filename, ext):
    return get_extension(filename) == ext


def is_csv(filename):
    return get_extension(filename) == ".csv"


def is_json(filename):
    return get_extension(filename) == ".json"


def is_xlsx(filename):
    return get_extension(filename) == ".xlsx"


def is_html(filename):
    return get_extension(filename) == ".html"


def is_txt(filename):
    return get_extension(filename) == ".txt"


# Change file  extension
def change_extension(filename, p_ext):
    path = get_directory(filename)
    base = get_basename(filename)
    ext = get_extension(filename)
    if (path == ""):
        return base.replace(ext, p_ext)
    else:
        return path + os.path.sep + base.replace(ext, p_ext)


def remove_extension(filename):
    return filename.replace(get_extension(filename), "")


# Change base rule_name of file, optionally extension
def change_basename(full_filename, filename, ext = ""):
    if (ext == ""): lExt = get_extension(full_filename)
    else: lExt = ext
    return get_directory(full_filename) + os.path.sep + filename + lExt


###
### System Info
###


def get_sys(sysData: dict = None) -> dict:
    if (sysData == None):
        sysData = dict()
    sysData["Name"]        = socket.gethostname()
    sysData["FQDN"]        = socket.getfqdn()
    sysData["Sys Platf."]  = sys.platform
    sysData["Machine"]     = platform.machine()
    sysData["Node"]        = platform.node()
    sysData["Platform"]    = platform.platform()
    sysData["Processor"]   = platform.processor()
    sysData["System OS"]   = platform.system()
    sysData["Release"]     = platform.release()
    sysData["Version"]     = platform.version()
    # sysData["Number CPUs"] = str(psutil.cpu_count())
    # sysData["Phys. CPUs"]  = str(psutil.cpu_count(logical=False))
    sysData["CWD"]         = os.getcwd()
    sysData["Now"]         = str(datetime.datetime.now().replace(microsecond=0))
    sysData["Script"]      = getMainScript()
    return sysData


# Print System Data
def print_sys():
    print(to_json(get_sys()))


###
### Dict & List Hint
###


def addData(key: str, value, data: dict = None) -> dict:
    if (data == None):
        data = dict()
    data[key] = value
    return data

def dumpObject(o):
    pprint(vars(o))

def mergeDict(a: dict, b: dict) -> dict:
    if (a == None): return b
    if (b == None): return a
    return {**a, **b}

def diffDict(fist_dict: dict, second_dict: dict) -> dict:
    return { k : second_dict[k] for k in set(second_dict) - set(fist_dict) }

def appendList(a: list, b: list) -> list:
    if (a == None): return b
    if (b == None): return a
    for item in b:
        a.append(item)
    return a

# PATH = "KEY"  "KEY/SUBKEY" "KEY[LIST_INDEX]/SUBKEY"
def get_value_from_dict(the_dict: dict, path: str):
    my_path    = re.split("/|\[|\]|\(|\)", path)
    extraction = the_dict
    for el in my_path:
        if el == "" : continue
        if isinstance(extraction, dict):
            extraction = extraction.get(el, extraction)
        elif isinstance(extraction, list):
            extraction = extraction[int(el)]
        else:
            extraction = extraction[el]
    return extraction

# String Replacement from Dict Path Values
# ${KEY}  ${KEY/SUBKEY} ${KEY[LIST_INDEX]/SUBKEY}
def render_string(text: str, dc: dict) -> str:
    variables = list()
    for match in re.findall('\$\{[^}]*\}', text):
        variables.append(re.sub("^\${", "", re.sub("}$", "", match)))
    new_text = text
    for var in variables:
        value = get_value_from_dict(dc, var)
        if (value != None) :
            new_text = new_text.replace("${" + var + "}", str(get_value_from_dict(dc, var)))
    return new_text


def render_dict(dc: dict) -> dict:
    string = to_json(dc)
    string = render_string(string, dc)
    return loadJsonContent(string)


###
### Template
###


class Template():

    def __init__(self, text : str = "", name=None):
        self.setText(text)
        self.name = name

    def __repr__(self):
        if (self.name!=None):
            return "TemplateName="+self.name+"\n"+self.getText()
        else:
            return self.getText()

    def __str__(self):
        return self.__repr__()

    def setText(self, text:str):
        self.text = text

    def getText(self) -> str:
        if (("%24%7B" in self.text) and ("${" not in self.text)):
            return json_decode_multiline(self.text)
        return self.text

    def getName(self) -> str:
        if (self.name == None): return ""
        return self.name

    def getVariables(self):
        vars = list()
        for match in re.findall('\${[^}]*\}', self.getText()):
            vars.append(re.sub("^\${", "", re.sub("}$", "", match)))
        logger.debug("Variables in Template "+self.getName()+" : \n" +
                     "> Variables : "+str(vars)+"\n" +
                     self.getText())
        return vars

    def getMissingVariables(self, dct: dict=None):
        missing = list()
        for var in getTemplateVariablesFromTemplateText(self.getText()):
            if (dct == None):
                missing.append(var)
            elif (var not in dct):
                missing.append(var)
        logger.debug("Missing Variables in Template "+self.getName()+" : \n" +
                     "> Missing Variables : "+str(vars)+"\n" +
                     "> For Context : " + str(dct)+"\n" +
                     self.getText())
        return missing

    def getMissingVariablesFromList(self, lst: list = None):
        missing = list()
        for var in getTemplateVariablesFromTemplateText(self.getText()):
            if (lst == None):
                missing.append(var)
            elif (var not in lst):
                missing.append(var)
        logger.debug("Missing Variables in Template "+self.getName()+" : \n" +
                     "> Missing Variables : "+str(vars)+"\n" +
                     "> For List : " + str(lst)+"\n" +
                     self.getText())
        return missing

    def getCleanText(self):
        try:
            content = remove_between(self.getText(), "\n<%doc>Enrichers", "</%doc>\n")
            content = remove_between(content,   "\n<%doc>VersionControl", "</%doc>\n")
            content = remove_between(content,   "<%doc>Enrichers", "</%doc>")
            content = remove_between(content,   "<%doc>VersionControl", "</%doc>")
            return content
        except:
            return self.getText()

    def getEnrichers(self):
        try:
            enr = find_between(self.getText(), "<%doc>Enrichers", "</%doc>")
            if (enr == None):
                logger.debug("Enrichers in Template " + self.getName() + " : None")
                return list()
            enr = enr.strip();
            enrichers = loadDataContent(enr)
            logger.debug("Enrichers in Template " + self.getName() + " : \n" +
                         "> Enrichers : " + str(enrichers) + "\n" +
                         self.getText())
            return enrichers["Enrichers"]
        except:
            logger.exception("Error Fetching Enrichers in text : " + self.getText())
            return None

    def getVersionControl(self):
        try:
            vcc = find_between(self.getText(), "<%doc>VersionControl", "</%doc>")
            if (vcc == None):
                logger.debug("VersionControl in Template " + self.getName() + " : None")
                return None
            vcc = vcc.strip()
            lvc = loadDataContent(vcc)
            logger.debug("VersionControl in Template " + self.getName() + " : \n" +
                         "> VersionControl : " + str(lvc) + "\n" +
                         self.getText())
            return lvc["VersionControl"]
        except:
            logger.exception("Error Fetching VersionControl in text : " + self.getText())
            return None

    def render(self, dct: dict):
        try:
            logger.debug("Rendering Template Text " + self.getName() + " : \n" + self.getText())
            # Checking and setting as UNDEFINED, missing variables
            for var in getTemplateVariablesFromTemplateText(self.getText()):
                if var not in dct:
                    logger.error("For Template : "+self.getName()+" - Missing in Digital Context - Variable : <"+var+">")
                    dct[var] = "${"+var+"=UNDEFINED}"
                else:
                    logger.debug("For Template : "+self.getName()+" - Found in Digital Context - Variable : <"+var+">")
            template_text = renderTemplateForContext(self.getText())
            rendered_text = MakoTemplate(template_text).render(**dct)
            logger.debug("Template " + self.getName() + " : \n" +
                         "> Rendered Text : \n" +
                         rendered_text)
            return rendered_text
        except:
            logger.exception("Error Rendering Template "+self.getName()+" : "+exceptions.text_error_template().render())
            return None

    """
    def renderWithEnrichers(self, context: SuperDict):

        try:
            # Get Template Variables
            vars = getTemplateVariablesFromTemplateText(self.getText())
            logger.info("Template Variables : " + str(vars))

            # Find Missing Vars for Template Rendering
            missing_vars = getMissingVariablesFromTemplateText(self.getText(), context.data)
            logger.info("Missing Template Variables : " + str(missing_vars))

            # Collect Enrichers
            # Collect Template Enrichers
            tpl_enrs = getEnrichersFromTemplateText(self.getText())
            # Collect Global Enrichers in FS
            global_enrichers = list()
            fsm = fs.FileStoreFactory.getFileStoreManager()
            enrichers = fsm.getFileStore("Enrichers").listFiles()
            logger.info("Enrichers in FileStore : " + str(enrichers))
            # Load each Enrichers
            for enr_name in enrichers:
                logger.info("Loading Enrichers : " + str(enr_name))
                enr = fsm.getFileStore("Enrichers").loadFileData(enr_name)
                if "Enrichers" in enr:
                    global_enrichers = appendList(global_enrichers, enr["Enrichers"])
            all_enr = appendList(global_enrichers, tpl_enrs)
            logger.info("All Enrichers : " + str(all_enr))
            logger.info("Before Solving : " + str(context.get("rule_name")))

            # Create Dependency Graph & Solve it - it updates the context
            solver.EnrichersLogic.solvesGraphSet(context, all_enr, missing_vars, stopOnFailure=False)
            logger.info("After Solving : " + str(context.get("rule_name")))

            # Render Template
            notification_text = renderTemplateFromTemplateText(self.getText(), context.data)
            notification_text = renderTemplateFromTemplateText(notification_text, context.data)
            context.set("NotificationText", notification_text)
            logger.info("Notification Text : \n===\n" + notification_text + "\n===\n")
            logger.info("After Rendering : " + str(context.get("rule_name")))
            return notification_text
        except:
            logger.exception("Error Rendering Template "+self.getName()+" : "+exceptions.text_error_template().render())
            return None
    """

    def getDetails(self, ctx : dict = None, template_name : str = None) -> dict :
        dct = dict()
        self.name = template_name
        if (self.name):
            dct["TemplateName"]      = self.getName()
            dct["Name"]              = self.getName()
        dct["TemplateText"]         = vc.getContentfromContent(MAKO_FILE, self.getText())
        dct["Content"]              = json_encode_multiline(vc.getContentfromContent(MAKO_FILE, self.getText()))
        dct["Variables"]            = getTemplateVariablesFromTemplateText(self.getText())
        if (ctx):
            dct["MissingVariables"] = getMissingVariablesFromTemplateText(self.getText(), ctx)
            dct["DigitalContext"]   = ctx
            dct["Rendering"]        = renderTemplateFromTemplateText(self.getText(), ctx)
            vc.getContentfromContent(MAKO_FILE, self.getText())
        dct["VersionControl"]       = vc.getVCfromContent(MAKO_FILE, self.getText()).asDict()["VersionControl"]
        return dct

    @staticmethod   # Rendering
    def renderFile(p_template_filename : str, p_rendered_filename, p_context: dict):
        logger.info("Rendering : [" + p_template_filename)
        logger.info("   > into : [" + p_rendered_filename + "]")
        if (not safeFileExist(p_template_filename)):
            logger.error("renderFile : Template File not found : "+p_template_filename)
            return None
        template_string = loadFileContent(p_template_filename)
        # dos2unix magic !
        "\n".join(template_string.splitlines())
        # Rendering Template
        mako.runtime.UNDEFINED = 'MISSING_IN_CONTEXT'
        rendered_template = MakoTemplate(template_string).render(**p_context)
        # And Saving to File ...
        saveFileContent(rendered_template, p_rendered_filename)
        return Util.loadFileContent(p_rendered_filename)

###
### Static
###

def getTemplateByFile(template_filename: str) -> Template:
    try:
        logger.info("Getting Template File : <" + template_filename + ">")
        f = open(template_filename, "r")
        contents = f.read()
        f.close()
        return Template(contents)
    except:
        logger.exception("Error Reading Template File : <"+template_filename + ">")
        raise


def renderTemplateFromTemplateText(template_text: str, dct: dict):
    return Template(template_text).render(dct)


def renderWithEnrichersTemplateFromTemplateText(template_text: str, dct: dict):
    return Template(template_text).renderWithEnrichers(SuperDict(dct))


def getMissingVariablesFromTemplateText(template_text: str, dct: dict):
    return Template(template_text).getMissingVariables(dct)


def getMissingVariablesFromTemplateTextForVariables(template_text: str, lst: list):
    return Template(template_text).getMissingVariablesFromList(lst)


def getEnrichersFromTemplateText(template_text: str):
    return Template(template_text).getEnrichers()


def getVCFromTemplateText(template_text: str):
    return Template(template_text).getVersionControl()


def getTemplateVariablesFromTemplateText(template_text: str):
    return Template(template_text).getVariables()


def getTemplateDetailsFromTemplateText(template_text: str, ctx: dict = None, template_name : str = None ):
    return Template(template_text).getDetails(ctx, template_name = template_name)


# VAR PATH = ${KEY}           ${KEY/SUBKEY}              ${KEY[LIST_INDEX]/SUBKEY}
# =>       = context["KEY"]   context["KEY"]["SUBKEY"}   context["KEY"][LIST_INDEX]["SUBKEY"}
def renderTemplateForContext(text:str) -> str:
    variables = list()
    for match in re.findall('\${[^}]*\}', text):
        vars.append(re.sub("^\${", "", re.sub("}$", "", match)))
    new_text = text
    for var in vars:
        path = ""
        keys = re.split("/|\[|\]", var)
        for key in keys:
            if key == "" : continue
            if key.isdigit() :
                path = path + "[" + key + "]"
            else:
                path = path + "[\"" + key + "\"]"
        new_text = new_text.replace("${" + var + "}", "${context" + path + "}")
    return new_text


###
### SuperDict
###


UUID_KEY    = "__UUID__"
ERROR_KEY   = "__ERROR__"
NAME_KEY    = "__NAME__"
SOURCE_KEY  = "__SOURCE__"


# noinspection PyBroadException
class SuperDict():

    def __init__(self, data: dict = None, name: str = None, uuid : bool = False):
        self.name = name
        if (data == None):
            self.data = dict()
        else:
            if (isinstance(data, str)):
                dct = loadDataContent(data)
                self.data = loadDataContent(data)
                if (dct != None): self.data = dct
                else : self.data = { name : data }
            elif (isinstance(data, list)):
                self.data = { name : data }
            elif (isinstance(data, set)):
                self.data = { name : data}
            elif (isinstance(data, dict)):
                self.data = data
            elif (isinstance(data, SuperDict)):
                self.data = data.getAsData()
            else:
                raise NotImplementedError("Cannot use ["+str(type(data))+"] to init SuperDict")
        if (self.data == None):
            self.data = dict()
        if (name) and (not self.hasPath(NAME_KEY)):
            self.data[NAME_KEY] = name
        if (uuid) and (not self.hasPath(UUID_KEY)):
            self.data[UUID_KEY] = str(uid.uuid4())

    def __str__(self):
        return to_json(self.data)

    def __repr__(self):
        return to_json(self.data)

    def __setitem__(self, key, data):
        # if isinstance(data,str):
        #    data = json_encode_multiline(data)
        return self.setSuperPath(key, data)

    def __getitem__(self, key):
        data = self.getSuperPath(key)
        # if isinstance(data, str):
        #    data = json_decode_multiline(data)
        return data

    def __delitem__(self, key):
        return self.delSuperPath(key)

    def clean(self, obj=None, keys : list = ["__UUID__", "__NAME__"] ):
        keys.append("__UUID__")
        keys.append("__NAME__")
        if (obj == None):
            obj = self.data
        if isinstance(obj, dict):
            for key in keys :
                if key in obj: del obj[key]
            for key in obj.keys():
                if isinstance(obj[key], dict):
                    self.clean(obj[key], keys)
        if isinstance(obj, list):
            for val in obj:
                if isinstance(val, dict):
                    self.clean(val, keys)
        return self

    def copy(self):
        """Return deep copy of SuperDict"""
        return SuperDict(self.getAsData().copy())

    def setMultiline(self, key, value):
        if isinstance(value, str):
            value = json_encode_multiline(value)
        self.setSuperPath(key, value)
        return value

    def getMultiline(self, key):
        data = self.getSuperPath(key)
        if isinstance(data, str):
            data = json_decode_multiline(data)
        return data

    def encodeMultiline(self, key):
        data = self.getSuperPath(key)
        if isinstance(data, str):
            data = json_encode_multiline(data)
        self.setSuperPath(key, data)
        return data

    def decodeMultiline(self, key):
        data = self.getSuperPath(key)
        if isinstance(data, str):
            data = json_decode_multiline(data)
        self.setSuperPath(key, data)
        return data

    def yaml(self, indent=4, clean=True):
        fDict = self.getAsData()
        if (clean):
            if "__UUID__"  in fDict : del fDict["__UUID__"]
            if "__NAME__"  in fDict : del fDict["__NAME__"]
        return to_yaml(fDict, indent=indent)

    def json(self, indent=4, clean=True):
        fDict = self.getAsData()
        if (clean):
            if "__UUID__"  in fDict : del fDict["__UUID__"]
            if "__NAME__"  in fDict : del fDict["__NAME__"]
        return to_json(fDict, indent=indent)

    def flatten(self, sep: str = "/") -> dict:
        return flatten(self.getAsData(), sep)

    def flattenedText(self, path_sep : str = "/", key_value_sep: str = " = ", key_prefix : str = "\"", key_suffix : str = "\"",  val_prefix : str = "\"", val_suffix : str = "\"", clean=True) -> str:
        fDict = self.flatten(sep=path_sep)
        text = ""
        for key in list(fDict.keys()):
            if (not key): continue
            if ((clean) and (key in ["__UUID__", "__NAME__"])) : continue
            text = text + key_prefix + key + key_suffix + key_value_sep + val_prefix + str(fDict[key]) + val_suffix + "\n"
        return text

    def flattenedKeys(self, path_sep : str = "/", clean : bool = True) -> list():
        fDict = self.flatten(sep=path_sep)
        fList = list()
        for key in list(fDict.keys()):
            if (not key): continue
            if ((clean) and (key in ["__UUID__", "__NAME__"])) : continue
            fList.append(key)
        return fList

    def variables(self, path_sep : str = "/", var_sep: str = " = ", key_prefix : str = "\"", key_suffix : str = "\"",  prefix : str = "[", suffix : str = "]", clean : bool = True):
        fDict = self.flatten(sep=path_sep)
        text = ""
        for key in list(fDict.keys()):
            if (not key): continue
            if ((clean) and (key in ["__UUID__", "__NAME__"])) : continue
            text = text + key_prefix + key + key_suffix + var_sep
        text = prefix + text + suffix
        return text

    def getByCase(self, variableName: str, default: str = None):
        if (isinstance(variableName, str)):
            ## Getting the Value of Variable
            var = self.get(variableName)
            if (var == None): var = self.get(variableName[0].lower() + variableName[1:])
            if (var == None): var = self.get(variableName[0].upper() + variableName[1:])
            if (var == None): var = self.get(variableName.upper())
            if (var == None): var = self.get(variableName.lower())
            if (var == None): var = self.get(variableName.title())
            if (var != None): return var
        if (isinstance(variableName, list)):
            for var in variableName:
                v = self.getVariableValue(var)
                if (v != None): return v
        return default

    # Description
    def getDescription(self, default="N/D", key=None):
        if key :
            if self.isDict(key):    return SuperDict(self.get(key)).getDescription(default=default)
            elif self.isList(key):  return default
            elif self.hasPath(key): return str(self.get(key))
            return default
        DESCRIPTION_KEY = "__DESCRIPTION__"
        if DESCRIPTION_KEY in self.data: return self.data[DESCRIPTION_KEY]
        if "Description" in self.data:   return self.data["Description"]
        if "DESCRIPTION" in self.data:   return self.data["DESCRIPTION"]
        if "description" in self.data:   return self.data["description"]
        if "Comment" in self.data:       return self.data["Comment"]
        if "COMMENT" in self.data:       return self.data["COMMENT"]
        if "comment" in self.data:       return self.data["comment"]
        if DESCRIPTION_KEY in self.data: return self.data[DESCRIPTION_KEY]
        return default

    # Source
    def getSource(self, default="N/D", key=None):
        if key and self.isDict(key): return SuperDict(self.get(key)).getSource(default=default)
        if key and not self.isDict(key): return default
        if "source" in self.data:       return self.data["source"]
        if "SOURCE" in self.data:       return self.data["SOURCE"]
        if "source" in self.data:       return self.data["source"]
        if "__Source__" in self.data:   return self.data["__Source__"]
        if SOURCE_KEY in self.data:     return self.data[SOURCE_KEY]
        return default

    # Name Management
    def getName(self, default="NoName", key=None):
        if key :
            if self.isDict(key): return SuperDict(self.get(key)).clean().getName(default=default)
            return default
        if "Name"   in self.data: return self.data["Name"]
        if "NAME"   in self.data: return self.data["NAME"]
        if "name"   in self.data: return self.data["name"]
        if "Method" in self.data: return self.data["Method"]
        if "METHOD" in self.data: return self.data["METHOD"]
        if "method" in self.data: return self.data["method"]
        if NAME_KEY in self.data: return self.data[NAME_KEY]
        return default

    def setName(self, Name: str = None):
        if (Name == None):
            self.data[NAME_KEY] = "NoName"
        else:
            self.data[NAME_KEY] = Name
        return self.data[NAME_KEY]

    # UUID Management
    def getUUID(self):
        if UUID_KEY not in self.data:
            self.data[UUID_KEY] = str(uid.uuid4())
        return self.data[UUID_KEY]

    def setUUID(self, UUID: str = None):
        if (UUID == None):
            self.data[UUID_KEY] = str(uid.uuid4())
        else:
            self.data[UUID_KEY] = UUID
        return self.data[UUID_KEY]

    def flatten(self, sep: str = "/"):
        return fj.flatten(self.data, separator=sep)
        return flatten(self.data, sep)

    # Error Management
    def setError(self, message: str = "Undefined Error"):
        if (self.isError()):
            self.data[ERROR_KEY] = self.data[ERROR_KEY] + " \n" + message
        else:
            self.data[ERROR_KEY] = message

    def getError(self):
        if (self.isError()):
            return self.data[ERROR_KEY]
        else:
            return "-- No Error --"

    def isError(self, message: str = None):
        if (ERROR_KEY not in self.data): return False
        if (message == None): return True
        return self.data[ERROR_KEY] == message

    # Data Access
    def getAsDict(self) -> dict:
        return self.data

    # Data Access
    def getAsData(self) -> dict:
        return self.data

    def setAsData(self, data: dict) -> dict:
        self.data = data
        return self.data

    # in List, get listPath entry, dict with key = value
    def getListItem(self, listPath, key, value):
        lst = self.getPath(listPath)
        if (not isinstance(lst, list)) : return None
        for item in lst :
            if (not isinstance(item, dict)): continue
            if (not (key in item)): continue
            if (str(item[key]) == str(value)) : return item

    # in List, get entry with key = value, return sideKey value
    def getSideValue(self, listPath, sideKey, key, value):
        item = self.getListItem(listPath, key, value)
        if (item == None): return None
        if (not isinstance(item, dict)): return None
        if (not (sideKey in item)): return None
        return item[sideKey]

    # Find Item by Key recursively
    def getRecursive(self, key: str, default=None):
        try:
            v = _find_item(self.data, key)
            if (v != None): return v
            else: return default
        except:
            return default

    # Get Item by Key Path, with specified separator
    def getNested(self, key: str, sep="/", default=None):
        try:
            v = get_by_path(self.data, key.split(sep))
            if (v != None): return v
            else:
                logger.debug("Key not found : ["+key+"] - Defaulted to ["+str(default)+"]")
                return default
        except Exception:
            logger.debug("Key Exception : [" + key + "] - Defaulted to [" + str(default) + "]")
            return default

    # Get Item by Key Path, with specified separator
    def hasNested(self, key: str, sep="/"):
        try:
            return get_by_path(self.data, key.split(sep)) != None
        except:
            return False

    # Get Item by Key Path, with specified separator
    def setNested(self, key: str, value: str, sep=":"):
        return set_by_path(self.data, key.split(sep), value)

    # Get Item by Key Path, with / as separator
    def getPath(self, key: str, default=None):
        try:
            v = dpath.util.get(self.data, key)
            if (v != None): return v
            else:
                logger.debug("Key not found : ["+key+"] - Defaulted to ["+str(default)+"]")
                return default
        except:
            logger.debug("Key Exception : [" + key + "] - Defaulted to [" + str(default) + "]")
            return default

    # Del Item by Key Path, with / as separator
    def delPath(self, key: str):
        if not self.hasPath(key): return
        return dpath.util.delete(self.data, key)

        up_path  = re.sub("\/$", "", re.sub("[a-zA-Z0-9 ]*$", "", key))
        last_key = key.replace(up_path, "").replace("/", "")
        if (up_path == ""):
            data = self.data
        else:
            data = self.getPath(up_path)
        if (isinstance(data, list)):
            return data.pop(int(last_key))
        else:
            return data.pop(last_key)

    # Check if Item has Key Path, with / as separator
    def hasPath(self, key: str):
        return (self.getPath(key) != None)

    # Set Item by Key Path, with / as separator
    def setPath(self, key: str, value):
        if (value == None):
            self.delPath(key)
            return None
        if isinstance(value, SuperDict):
            value = value.getAsData()
        try:
            if (self.getPath(key) == None):
                return dpath.util.new(self.data, key, value)
            else:
                return dpath.util.set(self.data, key, value)
        except ValueError :  # More than one match
            return None
        except KeyError  :   # No match
            return None

    # Get Item by Key Path, with / as separator
    def get(self, key : str, default=None):
        try:
            v = self.getPath(key)
            if (v != None): return v
            else:
                logger.debug("Key not found : ["+key+"] - Defaulted to ["+str(default)+"]")
                return default
        except:
            logger.debug("Key Exception : [" + key + "] - Defaulted to [" + str(default) + "]")
            return default

        self.rules = json_decode_multiline(rl.get("Rules"))

    # Set Item by Key Path, with / as separator
    def set(self, key: str, value):
        if (value == None) and (self.hasPath(key)):
            self.delPath(key)
            return None
        return self.setPath(key, value)

    # Check key Path, with / as separator
    def has(self, key: str):
        return self.hasPath(key)

    # SuperPath : UpKey/Key[Index]SubKey
    def toSuperPath(self, path_key, removeDash: bool = True):
        if (not removeDash):
            return re.sub("\/$", "", path_key.replace("]/", "/").replace("/[", "/").replace("]", "/").replace("[", "/"))
        else:
            return re.sub("\/$", "", re.sub("\#$", "", self.toSuperPath(path_key, removeDash=False)))

    def isDashPath(self, path_key):
        if (path_key == None) or (path_key == ""): return False
        return self.toSuperPath(path_key, removeDash=False)[-1] == "#"

    def getSuperPath(self, path_key, default=None):
        try:
            if (self.isDashPath(path_key)):
                obj = self.getPath(self.toSuperPath(path_key), default)
                return len(obj)
            return self.getPath(self.toSuperPath(path_key), default)
        except:
            return False

    def isSuperPath(self, path_key):
        try:
            return self.hasPath(self.toSuperPath(path_key))
        except:
            return False

    def setSuperPath(self, path_key, value):
        try:
            if (self.isDashPath(path_key)):
                sp = self.toSuperPath(path_key)
                obj = self.getPath(sp)
                if (obj == None): obj = list()
                if (isinstance(obj, list)):
                    obj.append(value)
                    self.setPath(sp, obj)
                    return value
            return self.setPath(self.toSuperPath(path_key), value)
        except:
            logger.debug("setSuperPath : key error : "+path_key)
            return None

    def delSuperPath(self, path_key):
        try:
            return self.delPath(self.toSuperPath(path_key))
        except:
            logger.debug("delSuperPath : key error : "+path_key)
            return None

    # Merge Two Contexts
    def merge(self, b: dict) -> dict:
        if isinstance(b, SuperDict):
            return self.merge(b.data)
        if isinstance(b, dict):
            self.data = mergeDict(self.data, b)
            return self.data

    # Diff Two Contexts
    def diff(self, b: dict) -> Union[dict, None]:
        if isinstance(b, SuperDict):
            return self.diff(b.data)
        if isinstance(b, dict):
            af = SuperDict(self.data).flattenedKeys()
            bf = SuperDict(b).flattenedKeys()
            return diffDict(af, bf)
        return None

    # Set Kwargs Item by Key Path, with / as separator
    def setParams(self, **kwargs):
        for name, value in kwargs.items():
            self.setPath(name, value)

    ### Get All Key Variables
    def getKeyList(self, path) -> list:
        lst = list()
        if (path == None) : return lst
        if (path == "")   : return lst
        it = self.get(path)
        if (it == None) : return lst
        if (not isinstance(it, dict)) : return lst
        return SuperDict(it).flattenedKeys()

    # Check if Item is Dict
    def isDict(self, key: str):
        return isinstance(self.get(key), dict)

    # Check if Item is List
    def isList(self, key: str):
        return isinstance(self.get(key), list)

    # Check if Item is Leaf
    def isLeaf(self, key: str):
        return ((not isinstance(self.get(key), dict)) and (not isinstance(self.get(key), list)))

    # Accumulate
    def accumulate(self, key, value):
        values = self.get(key)
        if (values == None) :
            return self.set(key, value)
        if (isinstance(values, list)) :
            values.append(value)
            return self.set(key, values)
        new_values = list()
        new_values.append(values)
        new_values.append(value)
        return self.set(key, new_values)

    def find(self, jsonPath: str):
        return [match.value for match in parse(jsonPath).find(self.getAsData())]

    def findNext(self, jsonPath: str, value, field: str):
        # find path.tt[x].match == value, return path.tt[x].field
        lastField = jsonPath.replace(re.sub("[^.]+$", "", jsonPath), "")  # foo[*].bar -> bar
        for match in parse(jsonPath).find(self.getAsData()):
            if (match.value != value) : continue
            nPath = str(match.full_path).replace(lastField, field)
            return parse(nPath).find(self.getAsData())[0].value


# Flattening Nested Dictionary
# {'b:w': 3, 'b:u': 1, 'b:v:y': 2, 'b:v:x': 1, 'b:v:z': 3, 'a:r': 1, 'a:s': 2, 'a:t': 3}
def flatten(myDict, sep: str = ":"):
    newDict = {}
    for key, value in myDict.items():
        if type(value) == dict:
            fDict = {sep.join([key, _key]): _value for _key, _value in flatten(value, sep).items()}
            newDict.update(fDict)
        elif type(value) == list:
            i = 0
            for el in value :
                if type(el) == dict:
                    fDict = {sep.join([key, str(i), _key]): _value for _key, _value in flatten(el, sep).items()}
                    newDict.update(fDict)
                else:
                    newDict[sep.join([key, str(i)])] = value
                i = i+1
        else:
            newDict[key] = value
    return newDict


# Access a nested object in root by item sequence.
def get_by_path(root, items):
    return reduce(operator.getitem, items, root)


# Set a value in a nested object in root by item sequence.
def set_by_path(root, items, value):
    get_by_path(root, items[:-1])[items[-1]] = value


# Find Item by Key recursively
def _find_item(obj, key):
    if key in obj: return obj[key]
    for k, v in obj.items():
        if isinstance(v, dict):
            item = _find_item(v, key)
            if item is not None:
                return item
        elif isinstance(v, list):
            for i in v:
                if isinstance(i, dict):
                    item = _find_item(i, key)
                    if item is not None:
                        return item


def instanciateClass(modulename_classname):
    module_name, class_name = modulename_classname.rsplit(".", 1)
    return getattr(importlib.import_module(module_name), class_name)


def check_PythonSyntax(source, filename: str = "Source"):              # Return Module
    try:
        ast.parse(source, filename=filename)
    except Exception as e:
        lines = traceback.format_exc().splitlines()[-4:]
        text = ""
        for line in lines:
            text = text + "\n" + line
        logger.exception ("Rule Parsing Error : \n" + text + "\n" + str(e) + "\n" )
        raise SyntaxError("Rule Parsing Error : \n" + text + "\n" + str(e) + "\n" )

###
### Conditions - Text & List Representations
###


def getConditionsList2Text(key_list, or_sep : str = " OR ", and_sep : str = " AND ", clean=True):
    filters = to_list(key_list)
    if (filters == None) : return ""
    ftext = "("
    for lfilter in filters:
        for key in list(lfilter.keys()):
            if (not key): continue
            if ((clean) and (key in ["__UUID__", "__NAME__"])): continue
            ftext = ftext + '"' + key + '"="' + str(lfilter[key]) + '"'
            if (len(list(lfilter.keys())) - list(lfilter.keys()).index(key) != 1): ftext = ftext + and_sep
        ftext = re.sub(and_sep + "$", "", ftext)
        if (len(filters) - filters.index(lfilter) != 1): ftext = ftext + ")" + or_sep + "("
    ftext = ftext + ")"
    return ftext


def getConditionsText2List(text, or_sep : str = " OR ", and_sep : str = " AND "):
    text = text.replace('"="', '" : "')
    text = text.replace(and_sep, ' , ')
    text = text.replace(or_sep, ' } , { ')
    text = text.replace('("' , '"')
    text = text.replace('")' , '"')
    text = "[ {" + text + "} ]"
    list = loadDataString(text)
    return list

###
### Json Schema Generation and Validation
###


json_schema_for_schema_v7 = '''
{
    "$schema": "http://json-schema.org/draft-07/schema#",
    "$id": "http://json-schema.org/draft-07/schema#",
    "title": "Core schema meta-schema",
    "definitions": {
        "schemaArray": {
            "type": "array",
            "minItems": 1,
            "items": { "$ref": "#" }
        },
        "nonNegativeInteger": {
            "type": "integer",
            "minimum": 0
        },
        "nonNegativeIntegerDefault0": {
            "allOf": [
                { "$ref": "#/definitions/nonNegativeInteger" },
                { "default": 0 }
            ]
        },
        "simpleTypes": {
            "enum": [
                "array",
                "boolean",
                "integer",
                "null",
                "number",
                "object",
                "string"
            ]
        },
        "stringArray": {
            "type": "array",
            "items": { "type": "string" },
            "uniqueItems": true,
            "default": []
        }
    },
    "type": ["object", "boolean"],
    "properties": {
        "$id": {
            "type": "string",
            "format": "uri-reference"
        },
        "$schema": {
            "type": "string",
            "format": "uri"
        },
        "$ref": {
            "type": "string",
            "format": "uri-reference"
        },
        "$comment": {
            "type": "string"
        },
        "title": {
            "type": "string"
        },
        "description": {
            "type": "string"
        },
        "default": true,
        "readOnly": {
            "type": "boolean",
            "default": false
        },
        "writeOnly": {
            "type": "boolean",
            "default": false
        },
        "examples": {
            "type": "array",
            "items": true
        },
        "multipleOf": {
            "type": "number",
            "exclusiveMinimum": 0
        },
        "maximum": {
            "type": "number"
        },
        "exclusiveMaximum": {
            "type": "number"
        },
        "minimum": {
            "type": "number"
        },
        "exclusiveMinimum": {
            "type": "number"
        },
        "maxLength": { "$ref": "#/definitions/nonNegativeInteger" },
        "minLength": { "$ref": "#/definitions/nonNegativeIntegerDefault0" },
        "pattern": {
            "type": "string",
            "format": "regex"
        },
        "additionalItems": { "$ref": "#" },
        "items": {
            "anyOf": [
                { "$ref": "#" },
                { "$ref": "#/definitions/schemaArray" }
            ],
            "default": true
        },
        "maxItems": { "$ref": "#/definitions/nonNegativeInteger" },
        "minItems": { "$ref": "#/definitions/nonNegativeIntegerDefault0" },
        "uniqueItems": {
            "type": "boolean",
            "default": false
        },
        "contains": { "$ref": "#" },
        "maxProperties": { "$ref": "#/definitions/nonNegativeInteger" },
        "minProperties": { "$ref": "#/definitions/nonNegativeIntegerDefault0" },
        "required": { "$ref": "#/definitions/stringArray" },
        "additionalProperties": { "$ref": "#" },
        "definitions": {
            "type": "object",
            "additionalProperties": { "$ref": "#" },
            "default": {}
        },
        "properties": {
            "type": "object",
            "additionalProperties": { "$ref": "#" },
            "default": {}
        },
        "patternProperties": {
            "type": "object",
            "additionalProperties": { "$ref": "#" },
            "propertyNames": { "format": "regex" },
            "default": {}
        },
        "dependencies": {
            "type": "object",
            "additionalProperties": {
                "anyOf": [
                    { "$ref": "#" },
                    { "$ref": "#/definitions/stringArray" }
                ]
            }
        },
        "propertyNames": { "$ref": "#" },
        "const": true,
        "enum": {
            "type": "array",
            "items": true,
            "minItems": 1,
            "uniqueItems": true
        },
        "type": {
            "anyOf": [
                { "$ref": "#/definitions/simpleTypes" },
                {
                    "type": "array",
                    "items": { "$ref": "#/definitions/simpleTypes" },
                    "minItems": 1,
                    "uniqueItems": true
                }
            ]
        },
        "format": { "type": "string" },
        "contentMediaType": { "type": "string" },
        "contentEncoding": { "type": "string" },
        "if": { "$ref": "#" },
        "then": { "$ref": "#" },
        "else": { "$ref": "#" },
        "allOf": { "$ref": "#/definitions/schemaArray" },
        "anyOf": { "$ref": "#/definitions/schemaArray" },
        "oneOf": { "$ref": "#/definitions/schemaArray" },
        "not": { "$ref": "#" }
    },
    "default": true
}
'''

json_schema_for_schema_v4 = '''
{
    "id": "http://json-schema.org/draft-04/schema#",
    "$schema": "http://json-schema.org/draft-04/schema#",
    "description": "Core schema meta-schema",
    "definitions": {
        "schemaArray": {
            "type": "array",
            "minItems": 1,
            "items": { "$ref": "#" }
        },
        "positiveInteger": {
            "type": "integer",
            "minimum": 0
        },
        "positiveIntegerDefault0": {
            "allOf": [ { "$ref": "#/definitions/positiveInteger" }, { "default": 0 } ]
        },
        "simpleTypes": {
            "enum": [ "array", "boolean", "integer", "null", "number", "object", "string" ]
        },
        "stringArray": {
            "type": "array",
            "items": { "type": "string" },
            "minItems": 1,
            "uniqueItems": true
        }
    },
    "type": "object",
    "properties": {
        "id": {
            "type": "string"
        },
        "$schema": {
            "type": "string"
        },
        "title": {
            "type": "string"
        },
        "description": {
            "type": "string"
        },
        "default": {},
        "multipleOf": {
            "type": "number",
            "minimum": 0,
            "exclusiveMinimum": true
        },
        "maximum": {
            "type": "number"
        },
        "exclusiveMaximum": {
            "type": "boolean",
            "default": false
        },
        "minimum": {
            "type": "number"
        },
        "exclusiveMinimum": {
            "type": "boolean",
            "default": false
        },
        "maxLength": { "$ref": "#/definitions/positiveInteger" },
        "minLength": { "$ref": "#/definitions/positiveIntegerDefault0" },
        "pattern": {
            "type": "string",
            "format": "regex"
        },
        "additionalItems": {
            "anyOf": [
                { "type": "boolean" },
                { "$ref": "#" }
            ],
            "default": {}
        },
        "items": {
            "anyOf": [
                { "$ref": "#" },
                { "$ref": "#/definitions/schemaArray" }
            ],
            "default": {}
        },
        "maxItems": { "$ref": "#/definitions/positiveInteger" },
        "minItems": { "$ref": "#/definitions/positiveIntegerDefault0" },
        "uniqueItems": {
            "type": "boolean",
            "default": false
        },
        "maxProperties": { "$ref": "#/definitions/positiveInteger" },
        "minProperties": { "$ref": "#/definitions/positiveIntegerDefault0" },
        "required": { "$ref": "#/definitions/stringArray" },
        "additionalProperties": {
            "anyOf": [
                { "type": "boolean" },
                { "$ref": "#" }
            ],
            "default": {}
        },
        "definitions": {
            "type": "object",
            "additionalProperties": { "$ref": "#" },
            "default": {}
        },
        "properties": {
            "type": "object",
            "additionalProperties": { "$ref": "#" },
            "default": {}
        },
        "patternProperties": {
            "type": "object",
            "additionalProperties": { "$ref": "#" },
            "default": {}
        },
        "dependencies": {
            "type": "object",
            "additionalProperties": {
                "anyOf": [
                    { "$ref": "#" },
                    { "$ref": "#/definitions/stringArray" }
                ]
            }
        },
        "enum": {
            "type": "array",
            "minItems": 1,
            "uniqueItems": true
        },
        "type": {
            "anyOf": [
                { "$ref": "#/definitions/simpleTypes" },
                {
                    "type": "array",
                    "items": { "$ref": "#/definitions/simpleTypes" },
                    "minItems": 1,
                    "uniqueItems": true
                }
            ]
        },
        "format": { "type": "string" },
        "allOf": { "$ref": "#/definitions/schemaArray" },
        "anyOf": { "$ref": "#/definitions/schemaArray" },
        "oneOf": { "$ref": "#/definitions/schemaArray" },
        "not": { "$ref": "#" }
    },
    "dependencies": {
        "exclusiveMaximum": [ "maximum" ],
        "exclusiveMinimum": [ "minimum" ]
    },
    "default": {}
}
'''

json_schema_for_schema = json_schema_for_schema_v7


def get_schema_for_schema():
    return json_schema_for_schema

###
### Save and Load Data with Schema Check
###

# Schema Inference: https://jsonschema.net/


def validateThisSchema(schema_data):
    if (not isinstance(schema_data, dict)):
        schema_data = loadDataContent(schema_data)
    schema_for_schema = loadDataContent(get_schema_for_schema())
    return validateSchema(schema_data, schema_for_schema)


def validateSchema(instance, schema_data):
    try:
        if isinstance(schema_data, dict):
            schema = schema_data
        else:  # Assuming File Name
            schema = loadDataFile(schema_data)
        validate(instance=instance, schema=schema)
        logger.info("JSON Schema Validated OK")
        return schema
    except:
        # logger.exception("JSON Schema Validation Failed: " + str(schema_data))
        logger.info("JSON Schema Validation Failed.")
        raise


def loadDataFileWithSchema(file_name: str, schema):
    data   = loadDataFile(file_name)
    if (schema):
        schema = validateSchema(data, schema)
    return data, schema


def saveDataFileWithSchema(data, file_name: str, schema):
    if (schema):
        schema = validateSchema(data, schema)
    saveDataFile(data, file_name)
    return data, schema


def generateSchema(sampleObjects) -> dict :
    # https://pypi.org/project/genson/
    builder = SchemaBuilder()
    builder.add_schema({"type": "object", "properties": {}})
    # builder.add_object({"hi": "there"})
    # builder.add_object({"hi": 5})
    # schema = builder.to_json(indent=2) # TO_SCHEMA
    if (sampleObjects == None) : return builder.to_schema()
    if (isinstance(sampleObjects, SuperDict)):
        sampleObjects = sampleObjects.getAsData()
    # list of dict [ { } ,  { } ]
    if (isinstance(sampleObjects, list)):
        for sampleObject in sampleObjects:
            if (isinstance(sampleObject, dict)):
                builder.add_object(sampleObject)
        return builder.to_schema()
    # Simple dict { }
    if (isinstance(sampleObjects, dict)):
        builder.add_object(sampleObjects)
        return builder.to_schema()


class ObjectReader():

    def __init__(self):
        self.schema = None
        self.object = None

    def readObjectForThisSchema(self, schema_data : Union[str,dict], object : dict = None)-> dict :
        if (not isinstance(schema_data, dict)):
            schema_data = loadDataFile(schema_data)
        schema_data = SuperDict(schema_data)
        self.schema = schema_data
        if (not object) : object = dict()
        self.object = SuperDict(object)

        object_type = self.schema["name"]
        print("Reading Object : "+object_type)

        for property in self.schema["properties"]:
            prop = SuperDict(self.schema["properties"][property])
            # logger.info(to_json(prop.getAsData()))
            if (prop.has("$ref")):
                continue
            elif (prop.has("items")):
                continue
            elif ((prop.has("type")) and (prop.get("type") in ["boolean", "number", "string"])):
                object[prop.get("name", property)] = self.readBasicProperty(prop, property, prop.get("name", property))
            elif (prop.has("-$ref")):  # Reference to Other Object (Foreign Key)
                object[prop.get("name", property)] = self.readReferenceProperty(prop, property, prop.get("name", property))
        try:
            validateSchema(object,self.schema.getAsData())
            logger.info(to_json(object))
            return object
        except Exception as e:
            logger.error("Object : " + str(object_type) + " : \n" + to_json(object) + "\n" + str(e))
            return None
        return object

    def readBasicProperty(self, property_def: dict, prop_name: str = None, def_value: str = None) -> str:
        prop = SuperDict(property_def)

        prop_name = prop.get("name", prop_name)
        prop_type = prop.get("type", "string")
        prop_desc = prop.get("description", None)
        prop_expl = prop.get("example", None)
        prop_patn = prop.get("pattern", None)
        prop_mand = prop.get("mandatory", None)
        if (prop_mand):
            prop_mand = "" if (prop_mand.upper() in ["N", "NO", "FALSE"]) else "*"
        if (prop.has("-$ref")):  # Reference to Other Object (Foreign Key)
            prop_mand = "$"
        logger.info(to_json(prop.getAsData()))
        if (prop.has("$ref")):
            return None
        if (prop.has("items")):
            return None
        def_display = "[" + def_value + "] " if def_value else ""

        Term.print_blue("Reading Property (" + prop_type + ") : " + prop_name + " " + prop_mand)
        if (prop_desc): Term.print_yellow("> " + prop_desc)
        if (prop_expl): Term.print_yellow("E.g. : " + prop_expl)
        valid_input = False
        while (not valid_input):
            # Type : object / array / string / number / boolean / null
            if (prop_type == "string"):
                read_input = input("Enter String Value " + def_display + ": ")
            if (prop_type == "number"):
                read_input = input("Enter Number Value " + def_display + ": ")
            if (prop_type == "boolean"):
                read_input = input("Enter Boolean Value " + def_display + ": ")
            read_input = read_input.strip()
            if ((read_input == "") and (def_value != "")):
                read_input = def_value
            # print("["+read_input+"]")
            if ((prop_mand != "") and (read_input == "")):
                Term.print_red("Value is mandatory")
            if ((prop_patn) and not bool(re.match(prop_patn, read_input))):
                Term.print_red("Value [" + read_input + "] does not match pattern : [" + prop_patn + "]")
            valid_input = True
        return read_input

    def readReferenceProperty(self, property_def: dict, prop_name: str = None, def_value: str = None) -> str:
        prop = SuperDict(property_def)

        prop_desc = prop.get("description", None)
        prop_type = prop.get("type", None)
        prop_mand = "$"
        logger.info(to_json(prop.getAsData()))
        if (prop.has("$ref")):
            return None
        if (prop.has("items")):
            return None
        def_display = "[" + def_value + "] " if def_value else ""

        Term.print_blue("Reading Property (" + prop_type + ") : " + prop_name + " " + prop_mand)
        if (prop_desc): Term.print_yellow("> " + prop_desc)
        valid_input = False
        while (not valid_input):
            read_input = input("Enter String Reference Value " + def_display + ": ")
            read_input = read_input.strip()
            if ((read_input == "") and (def_value != "")):
                read_input = def_value
            # print("["+read_input+"]")
            if ((prop_mand != "") and (read_input == "")):
                Term.print_red("Value is mandatory")
            valid_input = True
        return read_input

###
### Instanciate Class from Module
###


def instanciateClass(modulename_classname):
    module_name, class_name = modulename_classname.rsplit(".", 1)
    return getattr(importlib.import_module(module_name), class_name)


def html_to_text(html: str) -> str:
    return BeautifulSoup(html, features="html.parser").get_text().replace('\n', '\n\n')

###
### Configuration Loader
###

currentConfiguration : SuperDict = None  # SuperDict


def getCurrentConfiguration():
    return currentConfiguration


def merge_Configuration(p_config):
    cfg = None
    if (isinstance(p_config, dict)):
        cfg = p_config
    elif (isinstance(p_config, SuperDict)):
        cfg = p_config.getAsData()
    else:
        return None
    global currentConfiguration
    if (currentConfiguration == None):
        currentConfiguration = SuperDict()
    currentConfiguration.merge(cfg)
    return currentConfiguration


def save_Configuration(p_filename, p_config: SuperDict, tag=""):
    logger.info("Saving "+tag+" : {}".format(p_filename))
    saveDataFile(p_config.getAsData(), p_filename, safe=False)


def load_Configuration(p_filename, tag) -> SuperDict:
    logger.info("Loading "+tag+" : {}".format(p_filename))
    data = loadFileData(p_filename)
    if (data != None):
        return SuperDict(data)
    else:
        logger.error("Failed Loading "+tag+" : {}".format(p_filename))
        return None


def init_Configuration(cfg_filename, cmd_line_arg=None, env_cfg_var=None, default_cfg: SuperDict = None, tag="Configuration") -> SuperDict:

    if (cfg_filename == None):
        cfg_filename = CONFIG_DIRECTORY + os.sep + getMainScript()+"_Configuration.json"

    p_filename = cfg_filename
    logger.info("Default " + tag + " File : [" + cfg_filename + "]")
    if (cmd_line_arg != None):
        p_filename = cmd_line_arg
        logger.info("Command Line " + tag + " File Defined : [" + p_filename + "]")
    elif (env_cfg_var != None):
        logger.info("Command Line " + tag + " File Not Defined.")
        e_filename = os.getenv(env_cfg_var, None)
        if e_filename:
            logger.info("Env. Var. " + tag + " File Defined : [" + env_cfg_var + "]")
            p_filename = e_filename
        else:
            logger.info("Env. Var. " + tag + " File Not Defined : [" + env_cfg_var + "]")
            p_filename = cfg_filename

    logger.info("Using  " + tag + " File Name: [" + p_filename + "]")
    def_FileName = get_directory(p_filename)+os.sep+get_nakedname(p_filename)+"_Default"+get_extension(p_filename)
    # Save Default Configuration as Reference
    current_cfg = default_cfg
    if (default_cfg != None):
        logger.info("Saving Default / Sample - " + tag + " : {}".format(def_FileName))
        save_Configuration(def_FileName, default_cfg, tag)
    # Load Specified Configuration
    if (safeFileExist(p_filename)):
        current_cfg = load_Configuration(p_filename, tag)
    else:
        # Save Configuration in Force
        logger.info("Saving " + tag + " in Use - " + tag + " : {}".format(p_filename))
        save_Configuration(cfg_filename, current_cfg, tag)
    logger.info("Loaded " + tag + " :\n {}".format(to_json(current_cfg.getAsData())))
    current_cfg["CONFIGURATION_FILE"] = p_filename
    global currentConfiguration
    currentConfiguration = current_cfg
    return current_cfg

###
### Read Argv Sample
###

def read_argv(argv) -> dict:

    logger.info("Command Line Arguments : "+str(argv))
    params = dict()
    usage  = 'Usage: -gui -c <ConfigurationFile.xlsx> -edit -d <Data_File.csv> -no_append -no_analysis -email [<to_address>] -browser -verbose -report  \
              -c <ConfigurationFile.xlsx> : Use Configuration File       \
              -xedit       : Edit Configuration File in Excel \
              -gui         : File Open Dialog for Configuration File \
              -d <Data_File.csv> : Use Data_File       \
              -no_append   : Do not append KPI to Data File \
              -no_analysis : Do not append KPI to Data File \
              -browser     : Display Report in Browser \
              -verbose     : Report on Standard Output \
              -report      : Generate Excel Report \
              -email [<to_address>] : Report Email to specific recipient \
           '
    try:
        opts, args = getopt.getopt(argv, "hd:rxe:vgnm:bc:", ["cfile=", "dfile=", "mail", "email", "browser", "no_append", "no_analysis", "verbose", "report" , "gui", "xedit"])
    except getopt.GetoptError:
        print(usage)
        raise
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print(usage)
            sys.exit()
        elif opt in ("-d", "--dfile"):
            params["data_file"] = arg
        elif opt in ("-c", "--cfile"):
            params["config_file"] = arg
        elif opt in ("-e", "--email"):
            params["report_to_address"] = arg
            params["report_email"] = True
        elif opt in ("-m", "--mail"):
            params["report_to_address"] = arg
            params["report_email"] = True
        elif opt in ("-x", "--xedit"):
            params["config_edit"] = True
        elif opt in ("-r", "--report"):
            params["report_excel"] = True
        elif opt in ("-v", "--verbose"):
            params["report_verbose"] = True
        elif opt in ("-g", "--gui"):
            params["select_gui"] = True
        elif opt in ("-n", "--no" , "-no_append"):
            params["report_append"] = False
        elif opt in ("-y", "--na", "-no_analysis"):
            params["report_analysis"] = False
        elif opt in ("-b", "--browser"):
            params["report_browser"] = True
    return params

###
### Translate
###


# noinspection PyBroadException
def translate(sourceLang, targetLang, sourceText):
    try:
        URI = "https://translate.googleapis.com/translate_a/single?client=gtx&sl=" \
              + sourceLang + "&tl=" + targetLang + "&dt=t&q=" + quote(sourceText)

        logger.info("Translate Lookup: " + URI)
        rest_response = requests.get(URI)
        if (rest_response.status_code != 200):
            logger.error("Translate Error : " + str(rest_response.status_code))
            return None
        translation = str(rest_response.text)
        translation = re.sub(sourceText, "", translation)
        translation = re.sub(",null.*]", "", translation)
        translation = re.sub("\[\[\[\"", "", translation)
        translation = re.sub("\",\"\".*", "", translation)
        logger.info("Translate Result : " + str(translation))
        return translation
    except:
        logger.exception("Translate Error")
        return "Translation Error"

'''

var url = "https://translate.googleapis.com/translate_a/single?client=gtx&sl=" 
          + sourceLang + "&tl=" + targetLang + "&dt=t&q=" + encodeURI(sourceText);
var result = JSON.parse(UrlFetchApp.fetch(url).getContentText());
translatedText = result[0][0][0];
var json = {
    'sourceText': sourceText,
    'translatedText': translatedText
};

https://translate.googleapis.com/translate_a/single?client=gtx&sl=fr-FR&tl=en-US&dt=t&q=bonjour

'''

###
### Dynamically Loaded
###

## Method (static) : # file[.py][.classname].method

sample_descriptor_params = {
    "Method"    : "Action.ActionREST_Post",
    "Parameters" : {
        "Server": "127.0.0.1:5000",
        "Request": "/user/{1}?age={2}",
        "Parameter1": "Subscriber.Name",
        "Parameter2": "Subscriber.Age",
    }
}

sample_descriptor_context  = {
    "Method"    : "Action.ActionREST_Post",
    "Context"   : "/Channels/ChannelEmail"
}


def import_PythonCode(pythonCode: str, moduleName: str):
    # Create blank module
    module = types.ModuleType(moduleName)
    # Populate the module with code
    exec(pythonCode, module.__dict__)
    return module


def get_ModuleName(method: str, safe: bool = False):
    mod_name = method.replace(".py", "").split(".")[0]
    logger.info("Module for method : ["+method+"] : "+mod_name)
    safe = safe
    return mod_name
    """
    logger.info("sys.modules : "+str(sys.modules))
    if (not safe):
        if mod_name in sys.modules:  return mod_name
    if "__"+mod_name in sys.modules: return "__"+mod_name
    if "__"+mod_name+"__Rules" in sys.modules: return "__"+mod_name+"__Rules"
    return None
    """


def get_Module(method: str, safe: bool = False):
    return __import__(get_ModuleName(method, safe))


def isModuleLoaded(mod_name, safe: bool = False):
    mod_name  = mod_name.replace(".py", "")  # Strip .py extension
    mod_name  = mod_name.split(".")[0]
    try:
        if (not safe) and (mod_name in sys.modules):
            return True
        if "__"+mod_name in sys.modules:
            return True
        return False
    except:
        return False


def get_ModuleVarValue(module, var_name, default, safe: bool = False):
    if (isinstance(module, str)):
        module = get_Module(module, safe)
    return getattr(module, var_name, default)


def get_ModuleFunction(module, fct_name, safe: bool = False):
    if (isinstance(module, str)):
        module = get_Module(module, safe)
    return getattr(module, fct_name)


def get_ModuleSourceCode(module, safe: bool = False):
    if (isinstance(module, str)):
        module = get_Module(module, safe)
    return inspect.getsource(module)


def get_MethodForCall(method: str, safe: bool = False):
    modname  = get_ModuleName(method, safe)
    if (modname == None) :
        logger.error("Looking for Module [" + str(method) + "] FAILED")
        return None
    classname = None
    if (len(method.split(".")) == 3):
        classname = method.split(".")[1]
        function  = method.split(".")[2]
        logger.info("Looking for Module [" + str(modname) + "] Class [" + str(classname) + "] Function [" + str(function) + "]")
    elif (len(method.split(".")) == 2):
        classname = None
        function  = method.split(".")[1]
        logger.info("Looking for Module ["+str(modname)+"] Function ["+str(function)+"]")
    else:
        logger.error("Invalid Method Name - Expected Format : [ModuleName[.ClassName].FunctionName]")
    module = __import__(modname)
    if (classname != None):
        func = getattr(locals().get(classname), function)
    else:
        func = getattr(module, function)
    if func == None:
        return None
    return func


def check_Method(method: str, safe: bool = False):
    return (get_MethodForCall(method, safe) != None)


def call_MethodParameters(method: str, params: dict, context : SuperDict = None, safe: bool = False):
    func = get_MethodForCall(method, safe)
    if (func == None): raise Exception("Method not Found : "+method)
    logger.info("Signature : ["+method+"] : "+str(inspect.getfullargspec(func)))
    logger.info("Calling: ["+method+"]  with Parameters ["+str(params)+"]")
    if call_hasContext(func):
        return func(**params, context=context)
    else:
        return func(**params)


def call_MethodContext(method: str, context: SuperDict, safe: bool = False):
    try:
        func = get_MethodForCall(method, safe)
        if (func == None): raise Exception("Method not Found : "+method)
        logger.info("Signature : ["+method+"] : "+str(inspect.getfullargspec(func)))
        logger.info("Calling: ["+method+"]  with Parameters ["+str(context)+"]")
        return func(context=context)
    except Exception as e :
        logger.exception("Exception calling method : "+method+"\n"+str(e))
        context.setError("Exception calling method : "+method)
        return None


def call_hasContext(func):
    if (isinstance(func, str)):
        function = get_MethodForCall(func)
    else:
        function = func
    return "context" in inspect.getfullargspec(function)[0]


def call_FromDescriptor(descriptor, context: SuperDict = None, safe: bool = False):
    desc = None 
    if (isinstance(descriptor, dict)):       desc = dict(descriptor) 
    if (isinstance(descriptor, SuperDict)):  desc = dict(descriptor.getAsData()) 
    if (desc == None):           raise Exception("[call_FromDescriptor] Descriptor is not a dict" + str(descriptor))
    if (not ("Method" in desc)): raise Exception("[call_FromDescriptor] No Method in Descriptor" + descriptor)
    if ("Result" in descriptor):         del descriptor["Result"]
    if ("Exception" in descriptor):      del descriptor["Exception"]
    if ("ExecutionError" in descriptor): del descriptor["ExecutionError"]

    # Call Method with Parameters
    if ("Parameters" in desc) :  # Call Method with Parameters
        try:
            result = call_MethodParameters(desc["Method"], desc["Parameters"], context=context)
            descriptor["Result"] = str(result)
        except Exception as e:
            descriptor["Exception"] = str(e)
        return descriptor
    # Call Method with Context
    if (context == None):           context = SuperDict(descriptor)
    if (isinstance(context, dict)): context = SuperDict(context)
    if ("Context" in desc) :
        path = desc["Context"]
        if (isinstance(path, dict)):
            dict_param = path
        if (isinstance(path, str)):
            if (path in [ "" , "/" ]):
                dict_param = context.getAsData()
            else:
                dict_param = context.getPath(path)
        if (dict_param == None): raise Exception("path not found in Context : ["+path+"] for action : " + str(descriptor))
    else:
        dict_param = context.getAsData()
    try:
        result = call_MethodContext(desc["Method"], SuperDict(dict_param).clean(), safe)
        descriptor["Result"] = str(result)
    except Exception as e:
        descriptor["Exception"] = str(e)
        lines = traceback.format_exc().splitlines()[-3:]
        text = ""
        for line in lines:
            text = text + "\n" + line
        descriptor["ExecutionError"] = text
    return descriptor


def import_SourceFile(source_filename):   # Return Module
    logger.info("Importing : "+source_filename)
    try:
        with open(source_filename, "rt") as file:
            ast.parse(file.read(), filename=source_filename)
    except Exception as e:
        logger.exception("Source Parsing Error : ")
        raise e
    module  = __import__(source_filename.replace(".py", ""))
    imp.reload(module)
    return module


def load_SourceFile(source_filepath):  # Compile and Load in Python Runtime Interpreter, return Module
    logger.info("Loading Source File : " + source_filepath)
    mod_name, file_ext = os.path.splitext(os.path.split(source_filepath)[-1])
    return SourceFileLoader(mod_name, source_filepath).load_module()


def check_SourceSyntax(sourceString: str, filename: str = "Source.py"):
    logger.info("CheckActionSyntax : "+sourceString)
    try:
        ast.parse(sourceString, filename=filename)
        return "Syntax OK"
    except Exception as e:
        lines = traceback.format_exc().splitlines()[-4:]
        text = ""
        for line in lines:
            text = text + "\n" + line
        logger.exception ("Source Parsing Error : \n" + text + "\n\n" + str(e))
        raise SyntaxError("Source Parsing Error : \n" + text + "\n\n" + str(e))


def load_SourceStringSafe(source, mod_name, genCode=False):
    mod_name  = "__"+mod_name
    mod_file  = mod_name+".py"
    content   = source
    try:
        if (genCode == True) or (not isModuleLoaded(mod_name)):
            logger.info("Saving Source File : " + mod_file)
            saveFileContent(content, mod_file)
            logger.info("Importing Source File : " + mod_file)
            module    = import_SourceFile(mod_file)
        else:
            logger.info("Looking up Source Module : " + mod_name)
            module    = import_SourceFile(mod_file)
        return module
    except Exception as e:
        logger.exception("Action Loading Failed : " + mod_file)
        raise e


def load_SourceFileSafe(source_file_name, genCode=False):
    try:
        logger.info("Loading Source File : " + str(source_file_name))
        module = get_nakedname(source_file_name)
        return load_SourceStringSafe(loadFileContent(source_file_name), module, genCode=genCode)
    except Exception as e:
        logger.exception("Source Loading Failed : " + str(source_file_name))
        raise e


def is_ModuleFunction(module, function):
    try:
        getattr(module, function)
        return True
    except:
        return False


def get_FunctionSourceCode(module, function):
    if (not is_ModuleFunction(module, function)) : return None
    func_text = inspect.getcomments(getattr(module, function))
    if (not func_text): func_text = ""
    lines = inspect.getsourcelines(getattr(module, function))
    for line in lines[0]:
        func_text = func_text + line
    text = func_text + "\n"
    return text


def get_ModuleVarValue(module, var_name, default):
    return getattr(module, var_name, default)

###
### Repository Store
###


class RepositoryStore():

    # To accumulate all Item for the Engine

    def __init__(self, storeName: str, data=None, schema=None, index_prefix="", description=""):
        if ((storeName) and (checkJson(storeName))):
            sDict = loadJsonContent(storeName)
            storeName = list(sDict.keys())[0]
            data      = sDict[storeName]
        self.index_prefix = index_prefix
        self.schema       = self.setSchema(schema=schema)
        self.storeName    = storeName
        self.description  = description
        self.storeItems   = list()
        if (data == None): return
        if isinstance(data, list):
            self.storeItems = data
        elif isinstance(data, SuperDict):
            data = data.getAsData()
        elif isinstance(data, dict):
            data = data
        elif isinstance(data, str):
            data = loadDataContent(data)
        else:
            data = loadDataContent(str(data))
        if (data == None):
            return
        if (storeName):
            if (storeName in data):
                self.storeItems = data[storeName]
                return
            # Injected Enrichers in Context
            elif "__" + self.storeName + "__" in data:
                self.storeItems = data["__"+self.storeName+"__"]
                return
        if (isinstance(data, list)):
            return
        else:
            self.storeItems.append(data)

    def __str__(self) -> str:
        return str(to_json(self.getAsData()))

    def getStoreName(self) -> str:
        return self.storeName

    def getAsData(self) -> dict:
        return { self.storeName : self.storeItems }

    def getAsString(self) -> str:
        return to_json(self.getAsData())

    def getByKeyValue(self, key: str, value: str):
        if (key == None):   return None
        if (value == None): return None
        for item in self.storeItems:
            if (key in item) and (item[key] == value):
                return item
        return None

    def getItemName(self, item, idx: int = -1):
        if (item == None): return None
        if (isinstance(item, str)):
            return item
        if (not isinstance(item, dict)):
            if (idx != -1): return self.index_prefix + str(idx)
            else: return self.index_prefix
        if ("Name" in item)      : return item["Name"]
        if ("NAME" in item)      : return item["NAME"]
        if ("name" in item)      : return item["name"]
        if ("Method" in item)    : return item["Method"]
        if ("__NAME__" in item)  : return item["__NAME__"]
        return self.index_prefix + str(idx)

    def getByName(self, name: str):
        if (name == None): return None
        if (name.startswith(self.storeName+"/")):  # Index Based Enrichers/3
            return self.getByIndex(name.replace(self.storeName+"/", ""))
        for item in self.storeItems:
            if (self.getItemName(item) == name):
                return item
        return None

    def getByIndex(self, index: str):
        if (index == None): return None
        try:
            idx = int(index)
            return self.storeItems[idx]
        except:
            return self.getByName(index)

    def getDescription(self, name: str = None):
        if (name == None) : return self.description
        it = self.getByName(name)
        if (it == None) : return "N/A"
        if (isinstance(it,str)) : return it
        if "Description" in it : return it["Description"]
        if "Comment"     in it : return it["Comment"]
        if "Name"        in it : return it["Name"]
        if "name"        in it : return it["name"]
        if "NAME"        in it : return it["NAME"]
        if "__NAME__"    in it : return it["__NAME__"]
        return "N/A"

    def getSource(self, name: str):
        it = self.getByName(name)
        if (it == None) : return "N/A"
        if "__SOURCE__" in it : return it["__SOURCE__"]
        if "__Source__" in it : return it["__Source__"]
        if   "Source"   in it : return it["Source"]
        if   "SOURCE"   in it : return it["SOURCE"]
        return "N/A"

    ### Get Repository
    def getRepository(self) -> dict:
        rep = dict()
        rep[self.storeName] = self.storeItems
        return rep

    ### Get All Items
    def getList(self) -> list:
        return self.storeItems

    def getItems(self) -> list:
        return self.storeItems

    ### Get by Get / From
    def getByKeyValue(self, key1: str, val1: str, key2: str = None, val2: str = None):
        item_list = list()
        if (key2 == None):
            for item in self.storeItems:
                if (key1 in item) and (item[key1] == val1):
                    item_list.append(item)
            return item_list
        elif (key1 == None):
            for item in self.storeItems:
                if (key2 in item) and (item[key2] == val2):
                    item_list.append(item)
            return item_list
        else:
            for item in self.storeItems:
                if (key1 in item) and (key2 in item) and (item[key1] == val1) and (item[key2] == val2):
                    item_list.append(item)
            return item_list

    ### Get All Item Names
    def getNames(self) -> list:
        names_list = list()
        for idx, item in enumerate(self.storeItems):
            names_list.append(self.getItemName(item, idx))
        return names_list

    ### Get All Items Variables
    def getValues(self, key: str) -> list:
        getKeyValues = list()
        for item in self.storeItems:
            if key in item:
                getKeyValues.append(item[key])
        return getKeyValues

    ### Get All Items Variables
    def getAsPythonText(self) -> str:
        return "" + self.storeName + " = " + to_json(self.getList())

    ### Get All Items Variables
    def getAsContent(self) -> str:
        return "" + self.storeName + " = " + to_json(self.getList())

    ### Get All Key Variables
    def getKeyList(self, itemName) -> list:
        lst = list()
        it = self.getByName(itemName)
        if (it == None) : return lst
        return SuperDict(it).flattenedKeys()

    ### Get Formatted Entry
    def format(self, itemName) -> str:
        if (self.storeName == "Enrichers"):
            # TODO : Move to Enricher and Invoke Methods from Enrichers
            dc = self.getByName(itemName)
            if (dc == None):
                return to_json(self.getByName(itemName))
            text = "Enricher   : "
            if ("Name" in dc):
                text = text + "[" + dc["Name"] + "]"
            if ("Comment" in dc):
                text = text + " " + dc["Comment"] + ""  + "\n"
            if ("Get" in dc):
                text = text + "Get        : [" + dc["Get"]      + "]\n"
            if ("From" in dc):
                text = text + "From       : [" + dc["From"]     + "]\n"
            if ("Method" in dc):
                text = text + "Method     : [" + dc["Method"]   + "]\n"
            if ("Parameters" in dc):
                text = text + "Parameters : \n"
                for param in dc["Parameters"]:
                    # TODO
                    text = text + "  " + param + " : " + "#TODO VALUE" + "\n"
            if ("Accessor" in dc):
                text = text + "Accessor   : [" + dc["Accessor"] + "]\n"
            return text
        else:
            return to_json(self.getByName(itemName))

    ### Get Description for Entry Field
    def varDescription(self, varName, inItems: list = None) -> Union[str, None]:
        if (self.storeName == "Events") or (self.storeName == "Contexts"):
            for item in self.storeItems:
                dc = SuperDict(item)
                if dc.has(varName):
                    text = self.storeName[:-1].ljust(9)
                    if inItems and ("Name" in item) and (item["Name"] not in inItems):
                        continue
                    if ("Name" in item):
                        name = " [" + item["Name"] + "]"
                        text = text + name.ljust(15)
                    text = text + " : " + str(dc.get(varName)) + ""
                    return text
        if (self.storeName == "Enrichers"):
            for item in self.storeItems:
                if varName == item["Get"]:
                    text = "Enricher".ljust(9)
                    if inItems and ("Name" in item) and (item["Name"] not in inItems):
                        continue
                    if ("Name" in item):
                        name = " [" + item["Name"] + "]"
                        text = text + name.ljust(15)
                    if ("Comment" in item):
                        text = text + " : " + item["Comment"] + ""
                    return text
        for item in self.storeItems:
            if varName == item["Name"]:
                text = self.storeName + " : "
                if ("Name" in item):
                    text = text + "[" + item["Name"] + "]"
                if ("Source" in item):
                    text = text + " " + item["Source"] + " - "
                if ("Comment" in item):
                    text = text + " " + item["Comment"] + ""
                if ("Description" in item):
                    text = text + " " + item["Description"] + ""
                return text
        return None

    ### Get Formatted Entry for Preview
    def preview(self, itemName) -> str:
        if (self.storeName == "Templates") or (self.storeName == "Rules"):
            dc = self.getByName(itemName)
            if (dc == None):
                return to_json(self.getByName(itemName))
            if ("Content" in dc):
                return json_decode_multiline(dc["Content"])
        if (self.storeName == "Enrichers"):
            # TODO : Move to Enricher and Invoke Methods from Enrichers
            dc = self.getByName(itemName)
            if (dc == None):
                return to_json(self.getByName(itemName))
            text = "Enricher   : "
            if ("Name" in dc):
                text = text + "[" + dc["Name"] + "]"
            if ("Comment" in dc):
                text = text + " " + dc["Comment"] + ""  + "\n"
            if ("Get" in dc):
                text = text + "Get        : [" + dc["Get"]      + "]\n"
            if ("From" in dc):
                text = text + "From       : [" + dc["From"]     + "]\n"
            if ("Method" in dc):
                text = text + "Method     : [" + dc["Method"]   + "]\n"
            if ("Parameters" in dc):
                text = text + "Parameters : \n"
                for param in dc["Parameters"]:
                    # TODO
                    text = text + "  " + param + " : " + "#TODO VALUE" + "\n"
            if ("Accessor" in dc):
                text = text + "Accessor   : [" + dc["Accessor"] + "]\n"
            return text
        else:
            dc = self.getByName(itemName)
            for key in [key for key in dc if key.startswith("__")]: del dc[key]
            return to_json(dc)

    ### Remove Item
    def _remove(self, storeItem):
        if (isinstance(storeItem, str)):
            name = storeItem
        elif ("Name" in storeItem):
            name = storeItem["Name"]
        else:
            name = None
        if (name == None): return False
        for idx, item in enumerate(self.storeItems):
            if ("Name" in item) and (item["Name"] == name):
                del self.storeItems[idx]

    ### Remove Item
    def remove(self, storeItem):
        self._remove(storeItem)

    ### Add and Save Item Store
    def add(self, storeItem, source: str = None, repository=True):
        if (storeItem == None):
            return False
        elif (isinstance(storeItem, str)):
            return self.add(loadDataContent(storeItem), source, repository)
        elif (isinstance(storeItem, RepositoryStore)):
            return self.add(storeItem.getList(), source, repository)
        elif (isinstance(storeItem, SuperDict)):
            return self.add(storeItem.getAsData(), source, repository)
        elif (isinstance(storeItem, list)):
            for item in storeItem:
                if (not self.add(item), source, repository):
                    return False
            return True
        elif (repository) and (self.storeName in storeItem) :
            for item in storeItem[self.storeName]:
                if (not self.add(item, source, repository)):
                    return False
            return True
        elif ("__"+self.storeName+"__" in storeItem) :
            for item in storeItem["__"+self.storeName+"__"]:
                if (not self.add(item), source, repository):
                    return False
            return True
        else:
            if ("GET"  in storeItem)    : storeItem["Get"]     = storeItem["GET"]
            if ("get"  in storeItem)    : storeItem["Get"]     = storeItem["get"]
            if ("FROM" in storeItem)    : storeItem["From"]    = storeItem["FROM"]
            if ("from" in storeItem)    : storeItem["From"]    = storeItem["from"]
            if ("NAME" in storeItem)    : storeItem["Name"]    = storeItem["NAME"]
            if ("name" in storeItem)    : storeItem["Name"]    = storeItem["name"]
            if (NAME_KEY in storeItem)    : storeItem["Name"]    = storeItem[NAME_KEY]
            if ("rule_name" in storeItem) : storeItem["Name"]    = storeItem["rule_name"]
            if ("METHOD" in storeItem)  : storeItem["Method"]  = storeItem["METHOD"]
            if ("method" in storeItem)  : storeItem["Method"]  = storeItem["method"]
            if ("CONTEXT" in storeItem) : storeItem["Context"] = storeItem["CONTEXT"]
            if ("context" in storeItem) : storeItem["Context"] = storeItem["context"]
            if ("Name" not in storeItem) and ("From" in storeItem) and ("Get" in storeItem):
                storeItem["Name"] = storeItem["From"] + ">" + storeItem["Get"]
            if ("Name" not in storeItem) and ("Method" in storeItem):
                storeItem["Name"] = storeItem["Method"]
            if ("Name" not in storeItem) and ("__SOURCE__" in storeItem):
                storeItem["Name"] = storeItem["__SOURCE__"]
            if ("__KEY__" not in storeItem) and ("Name" in storeItem):
                storeItem["__KEY__"] = storeItem["Name"]
            if ("Name" not in storeItem) :
                logger.error("Cannot add in Store ["+self.storeName+"] without a name :" + str(storeItem))
                return None
            if (self.getByName(storeItem["Name"])):
                logger.info("Replacing in Store ["+self.storeName+"] with :" + str(storeItem))
                self._remove(storeItem["Name"])
            if (source):
                storeItem["__SOURCE__"] = source
            self.storeItems.append(storeItem)
        return True

    ### Schema
    def getSchema(self):
        return self.schema

    ### Schema
    def setSchema(self, schema):
        schema = to_dict(schema)
        if (not schema) : return None
        if (validateThisSchema(schema)):
            self.schema = schema
            return self.schema
        return None

    @staticmethod
    def listToStoreItem(strList: list, itemName: str, defValue="value") -> dict():
        dItem = dict()
        dItem[NAME_KEY] = itemName
        for key in strList:
            dItem[key] = defValue
        return dItem

    @staticmethod
    def listToStore(strList: list, storeName: str, defValue="value") :
        dItem = dict()
        dItem[NAME_KEY] = storeName
        for key in strList:
            dItem[key] = defValue
        dstore = dict()
        dstore[storeName] = list()
        dstore[storeName].append(dItem)
        return RepositoryStore(storeName, dstore)


repositoryKeywords = ["repository", "repos", "rep" ]


class Repository(RepositoryStore):

    # To accumulate all Item for the Engine
    # Saved locally into "store_file"

    def __init__(self, storeName: str, default_data: list = None, storeSchemaFile : str = None):
        super().__init__(storeName)
        self.storeFile   = DATA_DIRECTORY + os.sep + self.storeName + "_Repository.json"
        self.schemaFile  = DATA_DIRECTORY + os.sep + self.storeName + "_Schema.json"
        self.currentFile = DATA_DIRECTORY + os.sep + self.storeName + "_Current.json"
        self.defaultFile = DATA_DIRECTORY + os.sep + self.storeName + "_Default.json"
        self.defaultData = dict()
        if (isinstance(default_data, list)):
            self.defaultData[self.storeName] = default_data
        if (isinstance(default_data, dict)):
            self.defaultData = default_data
        if (default_data == None):
            self.defaultData = None
        if (storeSchemaFile != None) and (safeFileExist(storeSchemaFile)):
            self.schemaFile = storeSchemaFile
        else:
            self.schemaFile = None

    ### Init Store
    def initStore(self):
        logger.info("Init Repository : [" + self.storeName + "]")
        if (self.defaultData != None):
            saveDataFile(self.default_data, self.defaultFile)
            if not safeFileExist(self.currentFile):
                saveDataFile(self.defaultData, self.currentFile)
        if safeFileExist(self.currentFile):
            self.readStore(self.currentFile)
        self.saveStore()
        try:
            if (safeFileExist(self.storeFile)):
                self.readStore()
            else:
                self.saveStore()
            return True
        except:
            logger.exception("Error Reading ["+self.storeName+"] Store File : "+self.storeFile)
            return False

    ### Read Store
    def readStore(self, file_name=None):
        if (file_name == None):
            file_name = self.storeFile
        try:
            logger.info("Loading Store [" + self.storeName + "] : <" + file_name + ">")
            data, schema = loadDataFileWithSchema(file_name, schema=self.schemaFile)
            if (data != None):
                self.storeItems = data[self.storeName]
            logger.debug("["+self.storeName+" - Store Loaded : " + to_json(self.storeItems))
            return True
        except:
            logger.exception("Error Reading ["+self.storeName+"] Store File : <" + file_name + ">")
            return False

    ### Save Store
    def saveStore(self, file_name=None):
        if (file_name == None):
            file_name = self.storeFile
        try:
            logger.debug("Saving ["+self.storeName+"] Store : <" + file_name + ">")
            data = dict()
            data[self.storeName] = self.storeItems
            schema = None
            if (safeFileExist(self.schemaFile)): schema = self.schemaFile
            data, schema = saveDataFileWithSchema(data=data, file_name=file_name, schema=schema)
            return True
        except:
            logger.exception("Error Writing ["+self.storeName+"] Store File : <" + file_name + ">")
            return False

    ### Add and Save Item Store
    def add(self, storeItem, source: str = None, repository=True):
        super().add(storeItem, source, repository)
        if (not self.saveStore()):
            self._remove(storeItem["Name"])
            return False
        return True

    ### Remove and Save Item Store
    def remove(self, storeItem):
        super().remove(storeItem)
        return self.saveStore()

###
### KeyStore Support
###


class AbstractKeyStore():

    def __init__(self, nameSpace: str = ANME_NAMESPACE):
        self.nameSpace = nameSpace

    def __str__(self):
        if (self.nameSpace == None): return ""
        return "["+str(self.nameSpace)+"]"

    def nameSpaceKey(self, key: str):
        if (self.nameSpace == None): return key
        return str(self.nameSpace)+key

    def getNameSpace(self):
        return str(self.nameSpace)

    def deleteNameSpace(self, nameSpace: str = None):
        ns = nameSpace
        if (ns == None): ns = self.nameSpace
        if (ns == None): return
        return self.deletePrefix(self.nameSpace)

    def get(self, key):
        raise NotImplemented("AbstractKeyStore.get : Not Implemented")

    def set(self, key, content):
        raise NotImplemented("AbstractKeyStore.set : Not Implemented")

    def delete(self, key):
        raise NotImplemented("AbstractKeyStore.set : Not Implemented")

    def deletePrefix(self, prefix: str):
        raise NotImplemented("AbstractKeyStore.deletePrefix : Not Implemented")

    def resetStore(self):
        raise NotImplemented("AbstractKeyStore.resetStore : Not Implemented")


'''

https://curl.trillworks.com/#json
https://curl.trillworks.com/#python

https://github.com/spulec/uncurl

"curl --header "Content-Type: application/json" -X POST --data '{"username":"xyz","password":"xyz"}' http://localhost:3000/api/login"

"curl 'https://pypi.python.org/pypi/uncurl' -H 'Accept-Encoding: gzip,deflate,sdch' -H 'Accept-Language: en-US,en;q=0.8' -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/33.0.1750.152 Safari/537.36' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H 'Cache-Control: max-age=0' -H 'Cookie: foo=bar;' -H 'Connection: keep-alive' --compressed"
requests.get("https://pypi.python.org/pypi/uncurl", headers={
    "Accept-Encoding": "gzip,deflate,sdch",
    "Accept-Language": "en-US,en;q=0.8",
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/33.0.1750.152 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Cache-Control": "max-age=0",
    "Connection": "keep-alive",
}, cookies={
    "foo": "bar",
})
'''

###
### Unit Test
###


class TestUncurlMethods(unittest.TestCase):

    def test_uncurl(self):
        u1 = "curl --header \"Content-Type: application/json\" -X POST --data '{\"username\":\"xyz\",\"password\":\"xyz\"}' http://localhost:3000/api/login"
        print(uncurl.parse(u1))
        u2 = "curl 'https://pypi.python.org/pypi/uncurl' -H 'Accept-Encoding: gzip,deflate,sdch'"
        print(uncurl.parse(u2))
        u3 = "curl 'https://pypi.python.org/pypi/uncurl' -H 'Accept-Encoding: gzip,deflate,sdch' -H 'Accept-Language: en-US,en;q=0.8' -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/33.0.1750.152 Safari/537.36' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H 'Cache-Control: max-age=0' -H 'Cookie: foo=bar;' -H 'Connection: keep-alive' --compressed"
        print(uncurl.parse(u3))
        context = uncurl.parse_context(u3)
        print(context.url)
        print(context.headers)


class TestUtilMethods(unittest.TestCase):

    def test_translate(self):
        text = translate("fr-FR", "en-GB", "Bonjour Monde !")
        self.assertEqual(text, "Hello World !")

    def test_JSON_YAML(self):
        dc1 = dict()
        dc1["TT"] = "TT"
        dc2 = dict()
        dc2["DD"] = "DD"
        dc = dict()
        dc["O1"] = dc1
        dc["O2"] = dc2
        jdc1 = '{\n    "TT": "TT"\n}'
        jdc2 = '{\n    "DD": "DD"\n}'
        jdc  = '{\n    "O1": {\n        "TT": "TT"\n    },\n    "O2": {\n        "DD": "DD"\n    }\n}'
        ydc1 = 'TT: TT\n'
        ydc2 = 'DD: DD\n'
        ydc  = 'O1:\n    TT: TT\nO2:\n    DD: DD\n'
        jFileName = "tt.json"
        rFileName = "tt.rule"
        yFileName = "tt.yaml"
        cFileName = "cc.json"

        self.assertEqual(to_json(dc1), jdc1)
        self.assertEqual(to_json(dc2), jdc2)
        self.assertEqual(to_json(dc),  jdc)
        self.assertEqual(to_yaml(dc1), ydc1)
        self.assertEqual(to_yaml(dc2), ydc2)
        self.assertEqual(to_yaml(dc),  ydc)

        safeFileRemove(jFileName)
        safeFileRemove(rFileName)
        safeFileRemove(yFileName)
        safeFileRemove(cFileName)

        with self.assertRaises(NameError): saveDataFile(dc, "tt.csv")
        with self.assertRaises(NameError): loadDataFile("tt.csv")

        self.assertEqual(safeFileExist(jFileName), False)
        saveDataFile(dc, jFileName)
        self.assertEqual(safeFileExist(jFileName), True)

        self.assertEqual(safeFileExist(rFileName), False)
        saveDataFile(dc, rFileName)
        self.assertEqual(safeFileExist(rFileName), True)

        self.assertEqual(safeFileExist(yFileName), False)
        saveDataFile(dc, yFileName)
        self.assertEqual(safeFileExist(yFileName), True)

        self.assertEqual(safeFileExist(cFileName), False)
        saveFileContent(jdc, cFileName)
        self.assertEqual(safeFileExist(cFileName), True)

        content = loadFileContent(cFileName)
        self.assertEqual(content, jdc)

        content = loadFileContent(yFileName)
        self.assertEqual(content, ydc)

        content = loadFileContent(rFileName)
        self.assertEqual(content, jdc)

        content = loadFileContent(jFileName)
        self.assertEqual(content, jdc)

        ldc = loadDataFile(jFileName)
        self.assertDictEqual(ldc, dc)

        ldc = loadDataFile(rFileName)
        self.assertDictEqual(ldc, dc)

        ldc = loadDataFile(yFileName)
        self.assertDictEqual(ldc, dc)

        self.assertDictEqual(loadDataContent(jdc), dc)
        self.assertDictEqual(loadDataContent(ydc), dc)

        safeFileRemove(jFileName)
        safeFileRemove(rFileName)
        safeFileRemove(yFileName)
        safeFileRemove(cFileName)

    def test_Between(self):
        self.assertEqual(find_between  ("./tt file.csv", "tt", "csv"), " file.")
        self.assertEqual(remove_between("./tt file.csv", "tt", "csv"), "./")

        self.assertEqual(find_between  ("./tt file.csv dd", "tt", "csv"), " file.")
        self.assertEqual(remove_between("./tt file.csv dd", "tt", "csv"), "./ dd")

        self.assertEqual(find_between  ("tt <%doc>Comment ./tt file.csv </%doc> Test", "<%doc>Comment", "</%doc>"), " ./tt file.csv ")
        self.assertEqual(remove_between("tt <%doc>Comment ./tt file.csv </%doc> Test", "<%doc>Comment", "</%doc>"), "tt  Test")

        self.assertEqual(find_between  ("tt '''Comment ./tt file.csv ''' Test", "'''Comment", "'''"), " ./tt file.csv ")
        self.assertEqual(remove_between("tt '''Comment ./tt file.csv ''' Test", "'''Comment", "'''"), "tt  Test")

        text = """
code
### Start
here
### End
end code
"""
        new_text = """
code
### Start
there
### End
end code
"""
        dd = replace_between(text, "\n### Start\n", "\n### End\n", "there")
        self.assertEqual(dd, new_text)

    def test_Sys(self):
        print_sys()

    def test_Misc(self):
        print(timestamp())

    def test_SafeFiles(self):
        print(safeTimestamp())
        tt = "tt"
        fileName = "tt.csv"
        backupFileName  = safeBackupFileName(fileName,  tt)
        deletedFileName = safeDeletedFileName(fileName, tt)
        updatedFileName = safeUpdatedFileName(fileName, tt)

        safeFileRemove(fileName)
        safeFileRemove(backupFileName)
        safeFileRemove(deletedFileName)
        safeFileRemove(updatedFileName)

        self.assertEqual(fileName, "tt.csv")                     # File does not exist
        self.assertEqual(backupFileName, "tt.csv.backup.tt")     # File does not exist
        self.assertEqual(deletedFileName, "tt.csv.deleted.tt")   # File does not exist
        self.assertEqual(updatedFileName, "tt.csv.updated.tt")   # File does not exist

        self.assertEqual(safeFileExist(fileName), False)      # File does not exist
        self.assertEqual(safeFileExist(updatedFileName), False)
        self.assertEqual(safeFileExist(backupFileName), False)
        self.assertEqual(safeFileExist(deletedFileName), False)

        self.assertEqual(safeUpdateFile(fileName, tt, "tt"), True)  # File Creation
        self.assertEqual(safeFileExist(fileName), True)
        self.assertEqual(safeFileExist(updatedFileName), False)
        self.assertEqual(safeFileExist(backupFileName), False)
        self.assertEqual(safeFileExist(deletedFileName), False)

        self.assertEqual(safeUpdateFile(fileName, tt, "tt"), True)  # Update File
        self.assertEqual(safeFileExist(fileName), True)
        self.assertEqual(safeFileExist(updatedFileName), True)
        self.assertEqual(safeFileExist(backupFileName), False)
        self.assertEqual(safeFileExist(deletedFileName), False)

        self.assertEqual(safeBackupFile(fileName+"tt", tt), False)  # File Does not Exist
        self.assertEqual(safeBackupFile(fileName, tt,), True)  # Backup File
        self.assertEqual(safeFileExist(fileName), True)
        self.assertEqual(safeFileExist(updatedFileName), True)
        self.assertEqual(safeFileExist(backupFileName), True)
        self.assertEqual(safeFileExist(deletedFileName), False)

        self.assertEqual(safeDeleteFile(fileName+"tt", tt), False)  # File Does not Exist
        self.assertEqual(safeDeleteFile(fileName, tt), True)  # Delete File
        self.assertEqual(safeFileExist(fileName), False)
        self.assertEqual(safeFileExist(updatedFileName), True)
        self.assertEqual(safeFileExist(backupFileName), True)
        self.assertEqual(safeFileExist(deletedFileName), True)

        safeFileRemove(fileName)
        safeFileRemove(backupFileName)
        safeFileRemove(deletedFileName)
        safeFileRemove(updatedFileName)

    def test_PathFunctions(self):
        self.assertEqual(get_directory    ("."+os.sep+"tt"+os.sep+"file.csv"),  "."+os.sep+"tt")
        self.assertEqual(get_basename     ("."+os.sep+"tt"+os.sep+"file.csv"),  "file.csv")
        self.assertEqual(get_nakedname    ("."+os.sep+"tt"+os.sep+"file.csv"),  "file")
        self.assertEqual(get_strippedname ("."+os.sep+"tt"+os.sep+"file.csv"),  "."+os.sep+"tt"+os.sep+"file")
        self.assertEqual(get_completename ("."+os.sep+"tt"+os.sep, "file.csv"), "."+os.sep+"tt"+os.sep+"file.csv")
        self.assertEqual(get_completename ("."+os.sep+"tt", "file.csv"),        "."+os.sep+"tt"+os.sep+"file.csv")
        self.assertEqual(get_completename ("."+os.sep+"tt"+os.sep, "."+os.sep+"file.csv"), "."+os.sep+"file.csv")

    def test_FileExtensions(self):

        self.assertEqual(get_extension("./tt"+os.sep+"file.csv"),  ".csv")
        self.assertEqual(get_extension("./tt"+os.sep+"file.html"), ".html")
        self.assertEqual(get_extension("./tt"+os.sep+"file.txt"),  ".txt")
        self.assertEqual(get_extension("./tt"+os.sep+"file.json"), ".json")
        self.assertEqual(get_extension("./tt"+os.sep+"file.xlsx"), ".xlsx")

        self.assertEqual(is_ext("./tt"+os.sep+"file.csvx", ".csvx"), True)
        self.assertEqual(is_ext("./tt"+os.sep+"file.csvx", ".csvy"), False)

        self.assertEqual(is_csv ("./tt"+os.sep+"file.csvx"),  False)
        self.assertEqual(is_txt ("./tt"+os.sep+"file.txtx"),  False)
        self.assertEqual(is_html("./tt"+os.sep+"file.htmlx"), False)
        self.assertEqual(is_xlsx("./tt"+os.sep+"file.xlsxx"), False)
        self.assertEqual(is_json("./tt"+os.sep+"file.jsonx"), False)

        self.assertEqual(is_csv ("./tt"+os.sep+"file.csv"),  True)
        self.assertEqual(is_txt ("./tt"+os.sep+"file.txt"),  True)
        self.assertEqual(is_html("./tt"+os.sep+"file.html"), True)
        self.assertEqual(is_xlsx("./tt"+os.sep+"file.xlsx"), True)
        self.assertEqual(is_json("./tt"+os.sep+"file.json"), True)

        self.assertEqual(change_extension("./tt"+os.sep+"file.xlsx", ".txt"), "./tt"+os.sep+"file.txt")
        self.assertEqual(change_extension("./tt"+os.sep+"file.txt", ".json"), "./tt"+os.sep+"file.json")
        self.assertEqual(change_extension("file.txt", ".json"), "file.json")

        self.assertEqual(change_basename("./tt" + os.sep + "file.txt", "new", ".json"), "./tt" + os.sep + "new.json")

    def test_Schema(self):

        schema = '''
           {
           "definitions": {},
           "$schema": "http://json-schema.org/draft-07/schema#",
           "$id": "http://example.com/root.json",
           "type": "object",
           "title": "The Root Schema",
           "required": [
             "O1",
             "O2"
           ],
           "properties": {
             "O1": {
               "$id": "#/properties/O1",
               "type": "object",
               "title": "The O1 Schema",
               "required": [
                 "TT"
               ],
               "properties": {
                 "TT": {
                   "$id": "#/properties/O1/properties/TT",
                   "type": "string",
                   "title": "The Tt Schema",
                   "default": "",
                   "examples": [
                     "TT"
                   ],
                   "pattern": "^(.*)$"
                 }
               }
             },
            "O2": {
               "$id": "#/properties/O2",
               "type": "object",
               "title": "The O2 Schema",
               "required": [
                 "DD"
               ],
               "properties": {
                 "DD": {
                   "$id": "#/properties/O2/properties/DD",
                   "type": "string",
                   "title": "The Dd Schema",
                   "default": "",
                   "examples": [
                     "DD"
                   ],
                   "pattern": "^(.*)$"
                 }
               }
             }
           }
         }
        '''

        okdc = '{       "O1": {        "TT": "TT"    },    "O2": {        "DD": "DD"    }}'
        notOKdc = '{    "O3": {        "TT": "TT"    },    "O2": {        "DD": "DD"    }}'

        jsonFile   = "test.json"
        schemaFile = "test.schema"
        schemaDC   = loadDataContent(schema)
        saveDataFile(schemaDC, schemaFile)

        # This does not work - do not on to validate we have a valid schema ...
        # try:
        #    validateThisSchema(loadDataContent(okdc))
        # except:
        #    self.assertEqual("validateThisSchema","Failed")

        self.assertDictEqual(schemaDC, validateSchema(loadDataContent(okdc), schemaDC))
        with self.assertRaises(ValidationError): validateSchema(loadDataContent(notOKdc), schemaDC)

        self.assertDictEqual(schemaDC, validateSchema(loadDataContent(okdc), schemaFile))
        with self.assertRaises(ValidationError): validateSchema(loadDataContent(notOKdc), schemaFile)

        rdc1, rsc1 = saveDataFileWithSchema(loadDataContent(okdc), jsonFile, schemaDC)
        self.assertEqual(safeFileExist(jsonFile), True)
        self.assertDictEqual(rdc1, loadDataContent(okdc))
        self.assertDictEqual(rsc1, schemaDC)
        rdc2, rsc2 = loadDataFileWithSchema(jsonFile, schemaDC)
        self.assertDictEqual(rdc2, loadDataContent(okdc))
        self.assertDictEqual(rsc2, schemaDC)

        safeFileRemove(jsonFile)
        with self.assertRaises(ValidationError): saveDataFileWithSchema(loadDataContent(notOKdc), jsonFile, schemaDC)
        self.assertEqual(safeFileExist(jsonFile), False)
        saveDataFile(notOKdc, jsonFile)
        with self.assertRaises(ValidationError): loadDataFileWithSchema(jsonFile, schemaDC)

        safeFileRemove(jsonFile)
        safeFileRemove(schemaFile)

    def test_Query(self):

        tt = dict()
        tt["TT"] = "TT"
        q = Query("GET", ANME_HTTP + "://host.com:5000/user/Nicholas", "/", tt)

        self.assertEqual(q.op, "GET")
        self.assertEqual(q.url, ANME_HTTP + "://host.com:5000/user/Nicholas")
        self.assertEqual(q.path, "/user/Nicholas")
        self.assertEqual(str(q.qp), "{}")
        self.assertEqual(str(q.qs), "{}")
        self.assertEqual(q.payload, {'TT': 'TT'})

        q = Query("GET", ANME_HTTP + "://host.com:5000/user/Nicholas;PP=QQ?DD=EE&DD=FF&GG=HH", "/", tt)

        self.assertEqual(q.op, "GET")
        self.assertEqual(q.url, ANME_HTTP + "://host.com:5000/user/Nicholas;PP=QQ?DD=EE&DD=FF&GG=HH")
        self.assertEqual(q.query, "DD=EE&DD=FF&GG=HH")
        self.assertEqual(str(q.qp), "{'PP': ['QQ']}")
        self.assertEqual(str(q.qs), "{'DD': ['EE', 'FF'], 'GG': ['HH']}")
        self.assertEqual(q.getParam("DD"), "EE")
        self.assertEqual(q.getParam("PP"), "QQ")
        self.assertEqual(q.getParam("GG"), "HH")
        self.assertEqual(q.payload, {'TT': 'TT'})

        data, code = q.response("TT", 404)
        self.assertEqual(data, "TT")
        self.assertEqual(code, 404)

        data, code = q.exception("TT", NameError("DD"), 404)
        self.assertEqual(data, "TT -> NameError : DD")
        self.assertEqual(code, 404)
        # data = exception.__class__.__name__ + " : " + str(exception)

    def test_evenMore(self):
        dc = addData("TT", "TT")
        self.assertEqual(str(dc), "{'TT': 'TT'}")
        dc = addData("SS", "SS", dc)
        self.assertEqual(str(dc), "{'TT': 'TT', 'SS': 'SS'}")

    def test_testMore(self):
        template_text = "TT ${VAR1}  ${VAR2/VAR22}  ${VAR3}  ${VAR4} ${VAR3[2]L32} ${VAR6.VAR} TT"

        dc = dict()
        dc["VAR1"] = "VAR1VALUE"
        dc["VAR2"] = dict()
        dc["VAR2"]["VAR22"] = "VAR22VALUE"
        mylist = list()
        mylist.append("L1")
        mylist.append("L2")
        dc2 = dict()
        dc2["L31"] = "TT1"
        dc2["L32"] = "TT2"
        mylist.append(dc2)
        dc["VAR3"] = mylist
        dc["VAR4"] = 44
        dc["VAR5"] = "${VAR3[2]L31}"
        dc["VAR6.VAR"] = "${VAR2/VAR22}"

        self.assertEqual(str(get_value_from_dict(dc, "VAR1")), "VAR1VALUE")
        self.assertEqual(str(get_value_from_dict(dc, "VAR2/VAR22")), "VAR22VALUE")
        self.assertEqual(str(get_value_from_dict(dc, "VAR2")), "{'VAR22': 'VAR22VALUE'}")
        self.assertEqual(str(get_value_from_dict(dc, "VAR3[0]")), "L1")
        self.assertEqual(str(get_value_from_dict(dc, "VAR3[1]")), "L2")
        self.assertEqual(str(get_value_from_dict(dc, "VAR3[2]L32")), "TT2")

        self.assertEqual(str(get_value_from_dict(dc, "VAR6.VAR")), "${VAR2/VAR22}")
        dc2 = render_dict(dc)
        self.assertEqual(str(get_value_from_dict(dc2, "VAR6.VAR")), "VAR22VALUE")

        text = render_string(template_text, dc2)
        self.assertEqual(text, "TT VAR1VALUE  VAR22VALUE  ['L1', 'L2', {'L31': 'TT1', 'L32': 'TT2'}]  44 TT2 VAR22VALUE TT")

    def test_ReadSchema(self):
        schema_file = "etc"+os.sep+"NEF_Catalog_DataModel"+os.sep+"_Schemas"+os.sep+"NEF_Catalog_DataModel_API_Schema.json"
        obj = { "id": "def_id", "API_Provider_Name": "def_pn", "YAML": "def_yaml", "API_Name": "def_name" }
        obj = ObjectReader().readObjectForThisSchema(schema_file,obj)
        print(str(obj))

class TestSuperDictMethods(unittest.TestCase):

    def setUp(self):
        dic = {
            "a": {
                "r": 1,
                "s": 2,
                "t": 3
            },
            "b": {
                "u": 1,
                "v": {
                    "x": 1,
                    "y": 2,
                    "z": 3
                },
                "w": 3
            }
        }
        self.dc = SuperDict(data=dic, name="TT")
        self.dc.set("TT", "TT")
        self.dc.setPath("TA/TD", "TD")
        self.dc.setPath("DD", "DD")
        self.dc.setPath("TT", "New DD")

    def test_More(self):
        dc2 = SuperDict(name="TT2")
        dc2.set("SS", "SS")
        self.assertEqual(dc2.getNested("SS"), "SS")
        self.assertEqual(dc2.getPath("SS"), "SS")
        self.assertEqual(dc2.getRecursive("SS"), "SS")
        dc2.set("SS", "TT")
        self.assertEqual(dc2.getNested("SS"), "TT")
        self.assertEqual(dc2.getPath("SS"), "TT")
        self.assertEqual(dc2.getRecursive("SS"), "TT")
        self.assertEqual(dc2.hasPath("SS"),  True)
        self.assertEqual(dc2.hasPath("TT"), False)

    def test_get(self):
        self.assertEqual(self.dc.getNested("a/r"), 1)
        self.assertEqual(self.dc.getPath("a/r"), 1)
        self.assertEqual(self.dc.getRecursive("z"), 3)
        self.assertEqual(self.dc.get("TT"), "New DD")

    def test_set(self):
        self.dc.set("SS", "SS")
        self.assertEqual(self.dc.getNested("SS"), "SS")
        self.assertEqual(self.dc.getPath("SS"), "SS")
        self.assertEqual(self.dc.getRecursive("SS"), "SS")
        self.dc.set("SS", "TT")
        self.assertEqual(self.dc.getNested("SS"), "TT")
        self.assertEqual(self.dc.getPath("SS"), "TT")
        self.assertEqual(self.dc.getRecursive("SS"), "TT")

    def test_setPath(self):
        self.dc.setPath("ZA/ZD", "ZD")
        # self.dc.setNested("ZB/ZC", "ZCC")
        self.assertEqual(self.dc.getRecursive("ZD"), "ZD")
        self.assertEqual(self.dc.getNested("ZA/ZD"), "ZD")
        self.assertEqual(self.dc.hasNested("ZA/ZD"),  True)
        self.assertEqual(self.dc.hasNested("za/zd"),  False)
        self.assertEqual(self.dc.getPath("ZA/ZD"), "ZD")
        self.assertEqual(self.dc.hasPath("ZA/ZD"),  True)
        self.assertEqual(self.dc.hasPath("za/zd"),  False)
        self.assertEqual(self.dc.hasPath("za/zz"),  False)
        self.assertEqual(self.dc.has ("ZA/ZD/DD"), False)

        # print (flatten(self.dc.data))
        self.assertEqual(str(flatten(self.dc.data)), "{'a:r': 1, 'a:s': 2, 'a:t': 3, 'b:u': 1, 'b:v:x': 1, 'b:v:y': 2, 'b:v:z': 3, 'b:w': 3, 'TT': 'New DD', 'TA:TD': 'TD', 'DD': 'DD', 'ZA:ZD': 'ZD'}")
        self.assertEqual(str(flatten(self.dc.data, "/")), "{'a/r': 1, 'a/s': 2, 'a/t': 3, 'b/u': 1, 'b/v/x': 1, 'b/v/y': 2, 'b/v/z': 3, 'b/w': 3, 'TT': 'New DD', 'TA/TD': 'TD', 'DD': 'DD', 'ZA/ZD': 'ZD'}")

        self.dc.setPath("ZA/List", [ "AA", "BB" ] )
        self.assertEqual(str(flatten(self.dc.data, "/")), "{'a/r': 1, 'a/s': 2, 'a/t': 3, 'b/u': 1, 'b/v/x': 1, 'b/v/y': 2, 'b/v/z': 3, 'b/w': 3, 'TT': 'New DD', 'TA/TD': 'TD', 'DD': 'DD', 'ZA/ZD': 'ZD', 'ZA/List': ['AA', 'BB']}")

    def test_set_extended(self):
        self.dc.setPath("WA/WD", "WD")
        self.assertEqual(self.dc.getNested("WA/WD"), "WD")
        self.assertEqual(self.dc.getPath("WA/WD"), "WD")
        self.assertEqual(self.dc.getRecursive("WD"), "WD")

    # VAR PATH = ${KEY}           ${KEY/SUBKEY}              ${KEY[LIST_INDEX]/SUBKEY}
    # =>       = context["KEY"]   context["KEY"]["SUBKEY"}   context["KEY"][LIST_INDEX]["SUBKEY"}
    def test_getSuperDict(self):
        ctx = SuperDict()
        ctx["TT"] = "TT"
        ctx["UU/BB"] = "BB"
        print(ctx)
        self.assertEqual(ctx.getPath("LL/1"), None)
        self.assertEqual(ctx.getPath("LL/1/L1"), None)
        # ctx["VV[0]/EE"] = "EE"
        # ctx[ctx.toPath("VV[0]/EE")] = "EE"

        data = {
            "AA" : "AA",
            "BB" : { "CC": "CC" },
            "DD" : { "EE": "EE" },
            "LL" : [ { "L0" : "L0" } , { "L1" : "L1" , "L2" : "L2" } ]
        }
        ctx2 = SuperDict(data)
        print(ctx2)
        self.assertNotEqual(ctx2.getPath("LL/1"), None)
        self.assertNotEqual(ctx2.getPath("LL/1/L1"), None)
        self.assertNotEqual(ctx2.getPath("LL/1/L2"), None)
        self.assertEqual(ctx2.getSuperPath("AA"), "AA")
        self.assertEqual(ctx2.getSuperPath("BB/CC"), "CC")
        self.assertEqual(ctx2.getSuperPath("LL[0]/L0"), "L0")
        # print(ctx2.getSuperPath("LL[#]"))
        # print(ctx2.getSuperPath("LL[1]/#"))

        self.assertNotEqual(ctx2.getSuperPath("BB/CC"), None)
        ctx2.delPath("BB/CC")
        self.assertEqual(ctx2.getSuperPath("BB/CC"), None)
        print(ctx2)

        self.assertNotEqual(ctx2.getSuperPath("DD"), None)
        ctx2.delPath("DD")
        self.assertEqual(ctx2.getSuperPath("DD"), None)
        print(ctx2)

        self.assertNotEqual(ctx2.getSuperPath("LL/0"), None)
        ctx2.delPath("LL/0")
        self.assertDictEqual(ctx2.getSuperPath("LL/0"), {'L1': 'L1', 'L2': 'L2'})
        print(ctx2)

        self.assertNotEqual(ctx2.getSuperPath("LL/0/L2"), None)
        ctx2.delPath("LL/0/L2")
        self.assertEqual(ctx2.getSuperPath("LL/0/L2"), None)
        print(ctx2)

    def test_setSuperDict(self):
        ctx = SuperDict()
        ctx["TT"] = "TT"
        ctx["UU/BB"] = "BB"
        print(ctx)
        self.assertEqual(ctx.getPath("TT"), "TT")
        self.assertEqual(ctx.getPath("UU/BB"), "BB")
        ctx["VV"] = []
        ctx["VV[1]"] = "EE"
        print(ctx)
        self.assertEqual(ctx.getSuperPath("VV[1]"), "EE")
        print(ctx)
        ctx["ZZ"] = []
        ctx["ZZ[1]"] = {}
        ctx["ZZ[1]/EE"] = "EE"
        print(ctx)
        self.assertEqual(ctx.getSuperPath("ZZ[1]EE"), "EE")
        print(ctx)
        ctx["ZZ[-1]/ZZ"] = "ZZ"
        print(ctx)

        data = {
            "AA" : "AA",
            "BB" : { "CC": "CC" },
            "DD" : { "EE": "EE" },
            "LL" : [ { "L0" : "L0" } , { "L1" : "L1" , "L2" : "L2" } ]
        }
        ctx2 = SuperDict(data)
        print(ctx2)
        self.assertNotEqual(ctx2.getPath("LL/1"), None)
        self.assertNotEqual(ctx2.getPath("LL/1/L1"), None)
        self.assertNotEqual(ctx2.getPath("LL/1/L2"), None)
        self.assertEqual(ctx2.getSuperPath("AA"), "AA")
        self.assertEqual(ctx2.getSuperPath("BB/CC"), "CC")
        self.assertEqual(ctx2.getSuperPath("LL[0]/L0"), "L0")
        self.assertEqual(ctx2.getSuperPath("LL[#]"), 2)      # Size of List
        self.assertEqual(ctx2.getSuperPath("LL[1]/#"), 2)    # Size of Dict
        self.assertEqual(ctx2.getSuperPath("LL[0]/L0#"), 2)  # Length of String
        ctx2.setSuperPath("LL[#]", { "L3" : "L3"})  # Append of List
        print(ctx2)
        self.assertEqual(ctx2.getSuperPath("LL[#]"), 3)
        self.assertEqual(ctx2.getSuperPath("LL[2]/L3"), "L3")

        self.assertNotEqual(ctx2.getSuperPath("BB/CC"), None)
        ctx2.delPath("BB/CC")
        self.assertEqual(ctx2.getSuperPath("BB/CC"), None)
        print(ctx2)

        self.assertNotEqual(ctx2.getSuperPath("DD"), None)
        ctx2.delPath("DD")
        self.assertEqual(ctx2.getSuperPath("DD"), None)
        print(ctx2)

        self.assertNotEqual(ctx2.getSuperPath("LL/1/L2"), None)
        ctx2.delPath("LL/1/L2")
        self.assertIsNone(ctx2.getSuperPath("LL/1/L2"))
        print(ctx2)

        self.assertNotEqual(ctx2.getSuperPath("LL/0"), None)
        ctx2.delPath("LL/0")
        self.assertIsNone(ctx2.getSuperPath("LL/0"))
        print(ctx2)

        print(ctx)
        print(ctx.flatten())

    def test_setParamsSuperDict(self):
        ctx = SuperDict()
        ctx.setParams(TT="TTV", BB="BB")
        print(ctx)
        self.assertEqual(ctx.getPath("TT"), "TTV")
        self.assertEqual(ctx.getPath("BB"), "BBV")
        print(ctx)

    def test_setActionSuperDict(self):
        ctx = SuperDict()
        ctx.setAction("TheAction",  TT="TTV", BB="BBV")
        print(ctx)
        self.assertEqual(ctx.getPath("__Actions__/TheAction/TT"), "TTV")
        self.assertEqual(ctx.getPath("__Actions__/TheAction/BB"), "BBV")
        print(ctx)

    def test_sysInfo(self):
        print_sys()

    def test_runBashRule(self):
        pass
        """
        inJson = {
            "AA" : "AA",
            "BB" : { "CC": "CC" },
            "DD" : { "EE": "EE" },
            "LL" : [ { "L0" : "L0" } , { "L1" : "L1" , "L2" : "L2" } ]
        }
        outJson = runBashRule(inJson, ruleName:str, ruleContent:str, ruleType:str) -> dict:
        """

    def test_jsonPath(self):
        tt = SuperDict({'foo': [{'baz': 1, 'foo': 3}, {'baz': 2, 'foo': 4}]})
        print(tt.find('foo[*].baz'))
        print(tt.findNext('foo[*].baz', 2, "foo"))

    def test_b64(self):
        data = "This is a string \nHello"
        # bin to b64
        b64  = to_bin_2_b64(data.encode('utf-8'))
        print(b64)
        dec  = str(to_b64_to_bin(b64).decode('utf-8'))
        print(dec)
        # str to b64
        b64  = to_str_2_b64(data)
        print(b64)
        dec  = to_b64_to_str(b64)
        print(dec)
        # b64 to file in clear
        to_b64_2_file(b64, "tt.bin")
        b64 = to_file_2_b64("tt.bin")
        print(b64)
        ss = loadFileContent("tt.bin")
        print(ss)
        safeFileRemove("tt.bin")

if __name__ == '__main__':
    unittest.main()
