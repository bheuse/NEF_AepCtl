#!/usr/bin/env python3
import os

import uvicorn
from fastapi import Depends, FastAPI, Query
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, PlainTextResponse
from enum import Enum
from threading import Thread
import Util as ut
import markdown
import sys
import argparse
import re

import aepctl as aep

app = FastAPI()


class ServiceName(str, Enum):
    fs = "fs"
    ds = "ds"
    ws = "ws"


@app.get("/")
async def root():
    with open('root.md', 'r') as f:
        text = f.read()
        html_content = markdown.markdown(text)
        return HTMLResponse(content=html_content, status_code=200)


@app.get("/readme")
async def root():
    with open('aepctl.md', 'r') as f:
        text = f.read()
        html_content = markdown.markdown(text)
        return HTMLResponse(content=html_content, status_code=200)


@app.get("/images/{images_id}")
async def get_images(images_id: str):
    return FileResponse("images" + os.sep + images_id)


@app.get("/examples/{dir_id}/{file_id}")
async def get_examples_file(dir_id: str, file_id: str):
    return FileResponse("examples" + os.sep + dir_id + os.sep + file_id)


def handle(command):
    print(command)
    result = aep.AepCtl.main(command, interactive=False)
    print(str(result))
    js_res = ut.loadDataContent(result)
    if (js_res):
        return JSONResponse(content=js_res, status_code=200)
    else:
        return PlainTextResponse(content=result, status_code=400)


@app.get("/fs/{ressource}/{command}/{identifier}/{payload}")
async def fs_command(ressource: str = "apis", command: str = "list", identifier: str = "names", payload: str = None):
    return handle("fs" + " " + ressource + " " + command + " " + identifier + " " + payload)


@app.get("/ws/{ressource}/{command}/{identifier}/{payload}")
async def ws_command(ressource: str = "apis", command: str = "list", identifier: str = "names", payload: str = " "):
    return handle("ws" + " " + ressource + " " + command + " " + identifier + " " + payload)


@app.get("/ds/{ressource}/{command}/{identifier}/{payload}")
async def ds_command(ressource: str = " ", command: str = " ", identifier: str = "names", payload: str = " "):
    return handle("ds" + " " + ressource + " " + command + " " + identifier + " " + payload)


class CustomQueryParams:
    def __init__(self,
                 service:    str = Query(description="Description for Service",    default=ServiceName.fs),
                 ressource:  str = Query(description="Description for Ressource",  default="apis"),
                 command:    str = Query(description="Description for Command",    default="list"),
                 identifier: str = Query(description="Description for Identifier", default="names"),
                 payload:    str = Query(description="Description for Payload",    default="")):
        self.service    = service
        self.ressource  = ressource
        self.command    = command
        self.identifier = identifier
        self.payload    = payload


@app.get("/aepctl")
async def aepctl(service: ServiceName=ServiceName.fs , ressource: str ="apis" , command: str = "list", identifier: str = "names", payload: str = " ", params: CustomQueryParams = Depends()):
    return handle(service + " " + ressource + " " + command + " " + identifier + " " + payload)


@app.get("/aep")
async def aep(prompt: str = "fs apis list names"):
    return handle(prompt)


# uvicorn eapctlms:app --reload
def main(argv=None, aepctlServer : str=None):
    if (aepctlServer):
        host = re.sub(":.*", "", aepctlServer)
        port = re.sub(".*:", "", aepctlServer)
    else:
        ## Gets IP and PORT from command line and parses them
        ServerInfo = argparse.ArgumentParser(prog='aepctl server')
        ServerInfo.add_argument("-n", "--host",   default='0.0.0.0')
        ServerInfo.add_argument("-p", "--port",   type=int, default='8080')
        ServerInfo = ServerInfo.parse_args(argv)
        host = ServerInfo.host
        port = ServerInfo.port
    # Start Server
    uvicorn.run(app, host=host, port=port)


def start_aepctlms(aepctlServer : str) -> str :
    thread = Thread(target=main(aepctlServer=aepctlServer), daemon=True)
    thread.start()
    return "aepctlms"

# Development command for realtime updates
# uvicorn eapctlms:app --reload

if __name__ == '__main__' :
    main(argv=sys.argv[1:])
