#!/usr/bin/env python3
import os
from typing import Union

import uvicorn
from fastapi import Depends, FastAPI, Query, Request, Path, Body, File, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, PlainTextResponse
from enum import Enum
from threading import Thread
import markdown
import sys
import argparse
import re
from aepctl import AepCtl
import Util as ut
import datetime
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


def handle(command, payload : Union[dict, str, File] = None):
    command = re.sub("^"+Tags.fs,   "fs",   command)
    command = re.sub("^"+Tags.ds,   "ds",   command)
    command = re.sub("^"+Tags.ws,   "ws",   command)
    command = re.sub("^"+Tags.tmf,  "tmf",  command)
    command = re.sub("^"+Tags.anme, "anme", command)
    logger.info("AepCtl Command " + str(command))
    payload_filename = ut.uuid()

    if (payload):
        if (isinstance(payload, dict)):  # JSON Request Body
            logger.info("AepCtl Payload \n" + ut.to_json(payload))
            payload_filename = "backup" + os.sep + payload_filename+"_payload.json"
            ut.saveJsonFile(payload, payload_filename)
            logger.info("Payload saved in : " + payload_filename)
            command = command + " " + payload_filename
        if (isinstance(payload, str)):  # FileName
            # payload = ut.loadData(str)
            ut.saveJsonFile(payload, payload_filename)
            payload_filename = payload
            logger.info("Payload saved in : " + payload_filename)
            command = command + " " + payload_filename
        if (isinstance(payload, UploadFile)):  # File
            payload_filename = "backup" + os.sep + payload_filename + "_" + payload.filename
            with open(payload_filename, "wb+") as file_object:
                file_object.write(payload.file.read())
            logger.info("Payload saved in : " + payload_filename)
            command = command + " " + payload_filename

        logger.info("AepCtl Command " + str(command))

    result = AepCtl.main(command, interactive=False)

    if (payload):
        ut.safeDeleteFile(payload_filename)
        logger.info("Payload deleted  : " + payload_filename)

    logger.info(str(result))
    js_res = ut.loadDataContent(result)
    if (js_res):
        return JSONResponse(content=js_res, status_code=200)
    else:
        return PlainTextResponse(content=result, status_code=400)


# <img src="https://www.amdocs.com/sites/default/files/Favicon-dark_0.png" width="50">

description = """

<img src="images/AepLogo.png" width="60">

Utility to manage the Amdocs Exposure Platform, in the flavour of kubectl and apictl for wso2. 

## [ReadMe for more.](readme)

"""


class Tags(str, Enum):
    fs     = "FileStore"
    ds     = "DataStore"
    ws     = "Wso2"
    tmf    = "Tmf Store"
    anme   = "Anme Store"
    aepctl = "AepCtl"
    root   = "Root"


tags_metadata = [
    {
        "name": Tags.aepctl,
        "description": "AepCtl Prompt like Operations.",
    },
    {
        "name": Tags.fs,
        "description": "Local File Store Operations.",
    },
    {
        "name": Tags.ds,
        "description": "Web UI BackEnd Data Store Operations.",
    },
    {
        "name": Tags.ws,
        "description": "Wso2 API Management Store Operations.",
        "externalDocs": {
            "description": "WSO2 Developer Portal Rest API",
            "url": "https://apim.docs.wso2.com/en/latest/reference/product-apis/devportal-apis/devportal-v2/devportal-v2/",
        },
    },
    {
        "name": Tags.root,
        "description": "AepCtl support operations.",
    },
]


app = FastAPI(
    title="AepCtl",
    description=description,
    version="0.0.1",
    terms_of_service="http://example.com/terms/",
    contact={
        "name": "Bernard Heuse",
        "url": "https://www.linkedin.com/in/bernard-heuse-16296a",
        "email": "bheuse@amdocs.com",
    },
    license_info={
        "name": "Apache 2.0",
        "url": "https://www.apache.org/licenses/LICENSE-2.0.html",
    },
    openapi_tags=tags_metadata
)


class ServiceName(str, Enum):
    fs   = "FileStore"
    ds   = "DataStore"
    ws   = "Wso2"
    tmf  = "Tmf"
    anme = "Anme"


class ListTypes(str, Enum):
    ids     = "ids"
    names   = "names"
    entries = "entries"
    help    = "help"


class AllResources(str, Enum):
    Providers     = "Providers"
    Articles      = "Articles"
    Categories    = "Categories"
    Collections   = "Collections"
    APIs          = "APIs"
    ApiBundles    = "ApiBundles"
    UsagePolicies = "UsagePolicies"
    Accounts      = "Accounts"
    Services      = "Services"
    Contacts      = "Contacts"
    Roles         = "Roles"
    Industries    = "Industries"
    UseCases      = "UseCases"
    Subscriptions = "Subscriptions"
    Policies      = "Policies"
    Products      = "Products"
    Applications  = "Applications"



###
### Root
###

class Root:

    class NoParams:
        pass

    @app.get("/", tags=[Tags.root])
    async def root(params : NoParams = Depends()):
        with open('root.md', 'r') as f:
            text = f.read()
            html_content = markdown.markdown(text)
            return HTMLResponse(content=html_content, status_code=200)

    @app.get("/config", tags=[Tags.root])
    async def get_configuration(params : NoParams = Depends()):
        return handle("fs config")


    @app.get("/commands", tags=[Tags.root])
    async def get_commands(params : NoParams = Depends()):
        return handle("commands")


    @app.get("/readme", tags=[Tags.root])
    async def readme(params : NoParams = Depends()):
        with open('aepctl.md', 'r') as f:
            text = f.read()
            html_content = markdown.markdown(text)
            return HTMLResponse(content=html_content, status_code=200)

    @app.get("/images/{file_name}", tags=[Tags.root])
    async def get_image(file_name : str = "AepLogo.png", download : bool = False):
        if (download):
            return FileResponse("images" + os.sep + file_name, media_type='application/octet-stream', filename=file_name)
        else:
            return FileResponse("images" + os.sep + file_name, filename=file_name)

    @app.get("/files/{file_name}", tags=[Tags.root])
    async def get_file(file_name : str = "factory-dataset.json"):
        return FileResponse("data" + os.sep + file_name, media_type='application/octet-stream', filename=file_name)

    @app.get("/examples/{dir_name}/{file_name}", tags=[Tags.root])
    async def get_examples_file(dir_name: str, file_name: str):
        return FileResponse("examples" + os.sep + dir_name + os.sep + file_name, media_type='application/octet-stream', filename=file_name)

###
### File Store
###


class FsResources(str, Enum):
    Providers     = "Providers"
    Articles      = "Articles"
    Categories    = "Categories"
    Collections   = "Collections"
    APIs          = "APIs"
    ApiBundles    = "ApiBundles"
    UsagePolicies = "UsagePolicies"
    Accounts      = "Accounts"
    Services      = "Services"
    Contacts      = "Contacts"
    Roles         = "Roles"
    Industries    = "Industries"
    UseCases      = "UseCases"
    Subscriptions = "Subscriptions"


class FsCommands(str, Enum):
    help      = "help"
    get       = "get"
    display   = "display"
    list      = "list"
    browse    = "browse"
    create    = "create"
    update    = "update"
    delete    = "delete"
    openapi   = "openapi"
    schema    = "schema"
    template  = "template"
    load      = "load"
    save      = "save"
    backup    = "backup"
    restore   = "restore"
    export    = "export"
    import_   = "import"
    provision = "provision"
    delete_all = "delete_all"


class FileStore:

    class NoParams:
        pass
    
    class FsParamsResourceList:
        def __init__(self,
                     resource : FsResources = Path (description="Resource", default=FsResources.APIs),
                     idNames  : ListTypes   = Query(description="List entries, names or ids",  default="names")):
            self.resource = resource
            self.idNames = idNames

    class FsParamsResourceIdentifier:
        def __init__(self,
                     resource   : FsResources = Path(description="Resource", default=FsResources.APIs),
                     identifier : str         = Path(description="Identifier or name", default="id")):
            self.resource = resource
            self.identifier = identifier

    class FsParams:
        def __init__(self,
                     resource: FsResources = Path(description="Resource",   default=FsResources.APIs),
                     command:  FsCommands  = Path(description="Command",    default=FsCommands.list),
                     identifier: str       = Path(description="Space if command has optional identifier", default=" "),
                     payload:    str       = Body(description="Payload",     default="")):
            self.resource = resource
            self.command = command
            self.identifier = identifier
            self.payload = payload

    @app.patch("/fs/{resource}/{command}/{identifier}", tags=[ServiceName.fs])
    async def file_store_command(params: FsParams = Depends()):
        return handle("fs" + " " + params.resource + " " + params.command + " " + params.identifier + " ", params.payload)

    @app.get("/fs", tags=[Tags.fs])
    async def file_store_list_resources_entities(params: NoParams = Depends()):
        return [e.value for e in FsResources]  # handle("fs stores")

    @app.get("/fs/{resource}", tags=[Tags.fs])
    async def file_store_list_resources(params: FsParamsResourceList = Depends()):
        return handle("fs" + " " + params.resource + " " + "list" + " " + params.idNames)

    @app.get("/fs/{resource}/{identifier}", tags=[Tags.fs])
    async def file_store_get_resource(params: FsParamsResourceIdentifier = Depends()):
        return handle("fs" + " " + params.resource + " " + "get"  + " " + params.identifier)

    @app.delete("/fs/{resource}/{identifier}", tags=[Tags.fs])
    async def file_store_delete_resource(params: FsParamsResourceIdentifier = Depends()):
        return handle("fs" + " " + params.resource + " " + "delete" + " " + params.identifier)

    @app.post("/fs/{resource}/{identifier}", tags=[Tags.fs])
    async def file_store_create_resource(params: FsParamsResourceIdentifier = Depends(), payload: str = Body(...)):
        return handle("fs" + " " + params.resource + " " + "save" + " " + params.identifier, payload)

    @app.put("/fs/{resource}/{identifier}", tags=[Tags.fs])
    async def file_store_put_resource(params: FsParamsResourceIdentifier = Depends(), payload: str = Body(...)):
        return handle("fs" + " " + params.resource + " " + "save" + " " + params.identifier, payload)

    @app.patch("/fs/load", tags=[Tags.fs])
    async def file_store_load_file(uploaded_file: UploadFile = File(...)):
        return handle("fs load", payload=uploaded_file)


###
### Wso2 Store
###

class Wso2Resources(str, Enum):
    Apis          = "Apis"
    Policies      = "Policies"
    Categories    = "Categories"
    Products      = "Products"
    Applications  = "Applications"
    Subscriptions = "Subscriptions"


class Ws02Store:

    @app.get("/ws/{resource}/{command}/{identifier}/{payload}", tags=[Tags.ds])
    async def ws_command(resource: str = "apis", command: str = "list", identifier: str = "names", payload: str = " ", request: Request = None):
        return handle("ws" + " " + resource + " " + command + " " + identifier + " " + payload, request.json())

    @app.get("/ds/{resource}/{command}/{identifier}/{payload}", tags=[Tags.ds])
    async def ds_command(resource: FsResources = " ", command: str = " ", identifier: str = "names", payload: str = " ", request: Request = None):
        return handle("ds" + " " + resource + " " + command + " " + identifier + " " + payload, request.json())

###
### AepCtl
###


class AepCtlRoot:

    class AepCtlParams:
        def __init__(self,
                     service:    ServiceName  = Query(description="Description for Service",    default=ServiceName.fs),
                     resource:   AllResources = Query(description="Description for Resource",   default=FsResources.APIs),
                     command:    str          = Query(description="Description for Command",    default="list"),
                     identifier: str          = Query(description="Description for Identifier", default=""),
                     payload:    dict         = Body (description="Description for Payload",    default={ "resource" : "json object" } )):
            self.service    = service
            self.resource   = resource
            self.command    = command
            self.identifier = identifier
            self.payload    = payload

    @app.patch("/aepctl", tags=[Tags.aepctl])
    async def aepctl_prompt_command(prompt: str = "fs apis list names", payload:dict = Body(description="Payload", default=None)):
        logger.info("aepctl_prompt_command")
        return handle(prompt, payload)

    @app.patch("/aep", tags=[Tags.aepctl])
    async def aep_query(params: AepCtlParams = Depends()):
        logger.info("aep_query")
        return handle(params.service + " " + params.resource + " " + params.command + " " + params.identifier, params.payload)


###
### Main
###


# uvicorn eapctlms:app --reload
def main(argv=None, aepctlServer : str=None):
    if (aepctlServer):
        host = re.sub(":.*", "", aepctlServer)
        port = re.sub(".*:", "", aepctlServer)
    else:
        ## Gets IP and PORT from command line and parses them
        ServerInfo = argparse.ArgumentParser(prog='aepctl server')
        ServerInfo.add_argument("-n", "--host",   default='localhost')
        ServerInfo.add_argument("-p", "--port",   type=int, default='8089')
        ServerInfo = ServerInfo.parse_args(argv)
        host = ServerInfo.host
        port = ServerInfo.port
    if (str(host).strip() == "") : host = "localhost"
    if (str(port).strip() == "") : port = "8080"
    # Start Server
    print("uvicorn on " + str(host) + ":" + str(port))
    logger.info("uvicorn on " + str(host) + ":" + str(port))
    uvicorn.run(app, host=host, port=int(port))


def start_aepctlms(aepctlServer : str = "localhost:8080") -> str :
    thread = Thread(target=main(aepctlServer=aepctlServer), daemon=True)
    thread.start()
    return "aepctlms"

# Development command for realtime updates
# uvicorn aepctlms:app --reload

if __name__ == '__main__' :
    main(argv=sys.argv[1:])
