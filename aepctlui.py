#!/usr/bin/env python3

from typing import Union
import PySimpleGUI as sg
import subprocess
import platform
import os
import threading
import re
import tempfile
import json
import logging
import Util as ut
import Util_GUI as utg
from threading import Thread
import aepctl as aep
import sys

logging.basicConfig(format='%(levelname)s:%(name)s:%(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

application          = "Amdocs Exposure Platform Management Console"
application_settings = "AEP Control"

aep_debug = "-v "
ut.Verbose.init_verbose(True)
hint_text = "Select Data Store ... >"

refresh_timeout = 200  # ms

extensionsSettings = {
    "Extensions"   :
        {
            "Enrichers" : "json" ,
            "Templates" : "mako",
            "Triggers"  : "json",
            "Actions"   : "json",
            "Events"    : "json",
            "Contexts"  : "json",
            "Rules"     : "rules",
            "Notifications"  : "json",
            "RuleEngines"    : "json"
        }
}


###
###  Layout
###

class Layout :

    # ------ Menu Definition ------ #
    @staticmethod
    def createMenuBrowse():
        return ['&Browse', ['All &Data ...::M_ALLDATA',
                               '&Events ...::M_EVENTS', '&Contexts ...::M_CONTEXTS', 'Enri&chers ...::M_ENRICHERS',
                               '&Rules ...::M_RULES',   '&Actions ...::M_ACTIONS',   '&Templates ...::M_TEMPLATES']]

    @staticmethod
    def createMenuDefinition():
        return [['&File',     ['&Exit::M_EXIT', '---',
                               'BackUp &FS Store::M_BACKUP_FS_STORE',              'BackUp &DS Store::M_BACKUP_DS_STORE',
                               'BackUp &WS Store::M_BACKUP_WS_STORE',               '---',
                                '&Import FS Store into DS::M_IMPORT_DS_STORE',     'E&xport DS Store to FS::M_EXPORT_DS_STORE',
                               '---',
                               '&Load DataSet into FS Store::M_LOAD_FS_STORE',     'Load DataSet into DS &Store::M_LOAD_DS_STORE']],
                ['&FS Store', ['&BackUp ...::M_FS_BACKUP',           '&Restore ...::M_FS_RESTORE',
                               '&Delete All::M_FS_DELETE_ALL',       '&Load Data Set ...::M_FS_LOAD',
                               '&Export to DS::M_FS_EXPORT_DS',      '&Import from DS::M_FS_IMPORT_DS',
                               '&Provision to WS::M_FS_PROVISION_WS']],
                ['&DS Store', ['&BackUp...::M_DS_BACKUP',            '&Restore ...::M_DS_RESTORE',
                               '&Delete All::M_DS_DELETE_ALL',       '&Load Data Set ...::M_DS_LOAD',
                               '&Export to FS::M_DS_EXPORT_FS',      '&Import from FS::M_DS_IMPORT_FS',
                               '&Provision to WS::M_DS_PROVISION_WS']],
                ['&WS Store', ['&BackUp::M_WS_BACKUP',
                               '&Provision from FS::M_WS_PROVISION_FS', '&Provision from DS::M_WS_PROVISION_DS',
                               '&Extract to FS::M_WS_EXTRACT_FS',       '&Extract to DS::M_WS_EXTRACT_DS']],
        # Layout.createMenuBrowse(),
                ['&Settings', ['Theme, &Editor ...::M_SETTINGS', 'Toggle &Output::M_TOGGLE_OUTPUT', 'Toggle &Debug::M_DEBUG']],
                ['&Help',     [ '&Error ...::M_ERROR', '&Configuration ...::M_CONFIG', '&Help ...::M_HELP', '---', '&About ...::M_ABOUT']]]

    @staticmethod
    def createSystemLayout():
        return [
            [sg.Text('System Management', size=(20, 1), justification='left', font=("Courier", 15, 'bold'), key='System/Header'),
             sg.Text('System Operations', size=(50, 1), justification='left', font=("Courier", 9, 'bold'),  key='System/Title')],
            [sg.Button(' System ', button_color=('white', 'springgreen4'), key='System/SystemBt'),
             sg.Button(' Environment ', button_color=('white', 'springgreen4'), key='System/EnvironmentBt'),
             sg.Button('  Reset  ', button_color=('white', 'firebrick3'), key='System/ResetBt'),
             sg.Button(' System Logs ', button_color=('white', 'blue'), key='System/SystemLogsBt'),
             sg.Button(' System Errors ', button_color=('white', 'orange'), key='System/SystemErrorsBt'),
             sg.Button(' Help ', button_color=('white', 'grey'), key='System/HelpBt'),
             sg.Button(' Requests ', button_color=('white', 'grey'), key='System/RequestsBt'),
             sg.Button(' Cluster Logs ', button_color=('white', 'blue'), key='System/ClusterLogsBt'),
             sg.Button(' Operations API ', button_color=('orange', 'white'), key='System/OperationsAPIBt')],
            [sg.Multiline(default_text='(Click a Button ^ )', size=(98, 35), font=("Courier", 10), key='System/Output')],
        ]

    @staticmethod
    def createAddButonsLayout(Resource: str):
        BtLayout = Layout.addButonsLayout(None,     Resource, 'Hello', color=('white', 'springgreen4'))
        BtLayout = Layout.addButonsLayout(BtLayout, Resource, 'World', color=('white', 'springgreen4'))
        return BtLayout

    @staticmethod
    def createOpenapiSchemaProvisionButonsLayout(Resource: str):
        BtLayout = Layout.addButonsLayout(None,     Resource, 'Schema', color=('springgreen4', 'white'))
        BtLayout = Layout.addButonsLayout(BtLayout, Resource, 'OpenAPI', color=('springgreen4', 'white'))
        if (Resource in ["FS Apis", "FS Categories", "FS Services", "FS Contacts",
                         "DS Apis", "DS Categories", "DS Services", "FS Contacts"]):
            BtLayout = Layout.addButonsLayout(BtLayout, Resource, 'Provision', color=('white', 'orange'))
        if (Resource in ["WS Apis"]):
            BtLayout = Layout.addButonsLayout(BtLayout, Resource, 'Details', color=('white', 'orange'))
        return BtLayout

    def createWso2ButonsLayout(Resource: str):
        BtLayout = None
        if (Resource in ["WS Apis"]):
            BtLayout = Layout.addButonsLayout(None,     Resource, 'Details',   color=('white', 'orange'))
            BtLayout = Layout.addButonsLayout(BtLayout, Resource, 'OpenAPI',   color=('white', 'orange'))
            BtLayout = Layout.addButonsLayout(BtLayout, Resource, 'Thumbnail', color=('white', 'orange'))
        return BtLayout

    @staticmethod
    def addButonsLayout(pLayout, Resource: str, Label : str, color=('white', 'springgreen4')):
        if (pLayout is None) : pLayout = [[]]
        return [pLayout[0] + [sg.Button(" "+Label+" ",   button_color=color, key=Resource+"/"+Label.strip()+"Bt")]]

    @staticmethod
    def createHeaderLayout(Resource : str):
        return [[sg.Text(Resource+" Management", size=(34, 1), justification='left', font=("Courier", 15, 'bold'),  key=Resource+"/Header"),
                 sg.Text(Resource+" Operations", size=(50, 1), justification='left', font=("Courier", 9, 'bold'),   key=Resource+"/Title"),
                 ],
                [sg.Text('Name       : ',  size=(15, 1)), sg.InputText(Resource+" Name", size=(40, 1),   key=Resource+"/Name"),
                 sg.Text('Identifier : ',  size=(8, 1)), sg.InputText('Identifier', size=(38, 1),        key=Resource+"/Identifier",  readonly=True),
                 ],
                [sg.Text('Description : ', size=(15, 1)), sg.InputText('Description', size=(91, 1),      key=Resource+"/Description", readonly=True),
                 ],
                []]

    @staticmethod
    def createButtonsLayout(Resource: str, buttonsList=None):
        default_button_list = [
                     sg.Button(' List ',    button_color=('white', 'springgreen4'), key=Resource + "/ListBt"),
                     sg.Button(' Load ',    button_color=('white', 'springgreen4'), key=Resource + "/LoadBt"),
                     sg.Button(' Check ',   button_color=('white', 'grey'), key=Resource + "/CheckBt"),
                     sg.Button(' BackUp ',  button_color=('white', 'grey'), key=Resource + "/BackUpBt"),
                     sg.Button(' Clear ',   button_color=('white', 'blue'), key=Resource + "/ClearBt"),
                     sg.Button(' New ',     button_color=('white', 'blue'), key=Resource + "/NewBt"),
                     sg.Button(' Edit ',    button_color=('white', 'blue'), key=Resource + "/EditBt"),
                     sg.Button(' Save ',    button_color=('white', 'blue'), key=Resource + "/SaveBt"),
                     sg.Button(' Delete ',  button_color=('white', 'firebrick3'), key=Resource + "/DeleteBt"),
                     ]
        if (not buttonsList) :
            return [default_button_list]
        else:
            return [default_button_list + buttonsList[0] ]

    @staticmethod
    def createBodyLayout(Resource : str) :  # , InitialText: str = "Text Input", withContext=False):
        return [[sg.Listbox(values=('(Click List)', ''), font=("Courier", 12), size=(20, 25), enable_events=True,  key=Resource+"/Listing"),
                 sg.Multiline(default_text="( < Select "+Resource+")", size=(55, 26), font=("Courier", 12), key=Resource+"/Text")]
                ]

    @staticmethod
    def resourceLayout(service : str, resource : str, buttonsList=None):
        key = service + " " + resource
        b = Layout.createButtonsLayout(key, buttonsList)
        # b = Layout.addButonsLayout(b, "Events", "Repository" , color=('black', 'white'))
        return Layout.createHeaderLayout(key) + b + Layout.createBodyLayout(key)

    @staticmethod
    def addTabTabGroup(TabList, Service : str, Resource: str, button_list=None):
        TabList.append(sg.Tab(Resource, Layout.resourceLayout(Service, Resource, button_list), key=Service+" "+Resource+"/"+Resource+"Tab", metadata=Service+" "+Resource))
        return TabList

    @staticmethod
    def createMainLayout():

        DS_CATALOG_TABLIST = []
        for resource in aep.AEP_CATALOG_RESSOURCES:
            service_resource = "DS " + str(resource).capitalize()
            DS_CATALOG_TABLIST = Layout.addTabTabGroup(DS_CATALOG_TABLIST, "DS", str(resource).capitalize(), Layout.createOpenapiSchemaProvisionButonsLayout(service_resource))
        DS_CATALOG_GROUP = [[sg.TabGroup([DS_CATALOG_TABLIST], enable_events=True, font=("Courier", 12), key='DS Catalog/Tabs')]]

        DS_USERS_TABLIST = []
        for resource in aep.AEP_APPLICATION_USER_PROFILES_RESSOURCES:
            service_resource = "DS " + str(resource).capitalize()
            DS_USERS_TABLIST = Layout.addTabTabGroup(DS_USERS_TABLIST, "DS", str(resource).capitalize(), Layout.createOpenapiSchemaProvisionButonsLayout(service_resource))
        DS_USERS_GROUP = [[sg.TabGroup([DS_USERS_TABLIST], enable_events=True, font=("Courier", 12), key='DS Users/Tabs')]]

        FS_CATALOG_TABLIST = []
        for resource in aep.AEP_CATALOG_RESSOURCES:
            service_resource = "FS " + str(resource).capitalize()
            FS_CATALOG_TABLIST = Layout.addTabTabGroup(FS_CATALOG_TABLIST, "FS", str(resource).capitalize(), Layout.createOpenapiSchemaProvisionButonsLayout(service_resource))
        FS_CATALOG_GROUP = [[sg.TabGroup([FS_CATALOG_TABLIST], enable_events=True, font=("Courier", 12), key='FS Catalog/Tabs')]]

        FS_USERS_TABLIST = []
        for resource in aep.AEP_APPLICATION_USER_PROFILES_RESSOURCES:
            service_resource = "FS " + str(resource).capitalize()
            FS_USERS_TABLIST = Layout.addTabTabGroup(FS_USERS_TABLIST, "FS", str(resource).capitalize(), Layout.createOpenapiSchemaProvisionButonsLayout(service_resource))
        FS_USERS_GROUP = [[sg.TabGroup([FS_USERS_TABLIST], enable_events=True, font=("Courier", 12), key='FS Users/Tabs')]]

        WS_TABLIST = []
        for resource in aep.WSO2_RESSOURCES:
            service_resource = "WS " + str(resource).capitalize()
            WS_TABLIST = Layout.addTabTabGroup(WS_TABLIST, "WS", str(resource).capitalize(), Layout.createWso2ButonsLayout(service_resource))
        WS_GROUP = [[sg.TabGroup([WS_TABLIST], enable_events=True, font=("Courier", 12), key='WS WSO2/Tabs')]]

        TAB_GROUP = sg.TabGroup([[sg.Tab(' FS Catalog ', FS_CATALOG_GROUP,     font=("Courier", 12), background_color='red',     key='FS_CatalogTab'),
                                  sg.Tab(' FS Users ',   FS_USERS_GROUP,       font=("Courier", 12), background_color='red',     key='FS_UsersTab'),
                                  sg.Tab(' DS Catalog ', DS_CATALOG_GROUP,     font=("Courier", 12), background_color='green',   key='DS_CatalogTab'),
                                  sg.Tab(' DS Users ',   DS_USERS_GROUP,       font=("Courier", 12), background_color='green',   key='DS_UsersTab'),
                                  sg.Tab(' WS WSO2 ',    WS_GROUP,             font=("Courier", 12), background_color='blue',    key='WS_Tab'),
                                  sg.Tab(' System ',     Layout.createSystemLayout(),  font=("Courier", 12),                     key='System_Tab')]],
                    enable_events=True, font=("Courier", 12), key='Tabs')

        mainLayout = [
                  [sg.Menu(Layout.createMenuDefinition(), tearoff=True)],
                  [sg.Text(application, size=(50, 1), justification='left', font=("Courier", 20, 'bold'), key='Title')],
                  [sg.Text('OK', text_color="green", size=(100, 1), key='Status')],
                  [TAB_GROUP],
                  [sg.StatusBar(' Status and Errors ', key="-STATUS-", pad=(2, 2), size=(33, 1), tooltip='Status and Errors')]
          ]
        return mainLayout


class MainGUI(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)
        self.application     = application  # Application Name
        self.window          = None  # sg window
        self.current_event   = None  # Current Read Event (e.g. "FS Providers/SaveBt")
        self.current_values  = None  # Current Widget Values
        self.udata                 = None
        self.runTime               = None
        self.current_content       = None
        self.current_content_file  = None
        self.current_content_ext   = None
        self.current_tab     = None  # Widget prefix (usually the Tab (e.g. "FS Providers")
        self.current_widget  = None  # Widget name without Suffix (e.g. SaveBt)
        self.current_value   = None  # Value of the current widget
        self.current_action  = None  # Widget without Suffix (e.g. Save)
        self.current_element = None  # Name of the current element (i.e. of "FS Providers/Name")
        self.current_list    = None  # List of elements of the current resource (i.e. of "FS Providers/List")
        self.Resource        = None  # Resource name (e.g. FS Provider)
        self.Resources       = None  # Resource name plural (e.g. FS Providers)
        self.resources       = None  # Resource name lower case (e.g. fs providers)
        self.error_text      = None  # Current Error message, None = no error
        self.no_refresh      = None  # Do not refresh the window before reading next event
        self.output_popup    = None  # If a window pops up for each result of a remote command
        self.last_output     = None  # Last result of a remote command
        self.theme           = None  # Window Look and Feel
        self.editor          = None  # External Editor Location
        self.aep_service     = None  # FS / DS / WS
        self.aep_store       = None  # Providers / Articles etc ...
        self.aepctl_last_command = None
        self.aepctl_last_result  = None
        self.initWindow()

    def error(self, text : Union[str, None] ="Error"):
        if (not text):  # Reset Error
            self.error_text  = None
            return
        self.error_text  = str(text) + "\n" + str(self.error_text)
        self.status(self.current_event + " - ERROR : " + text , "red")
        logger.error(self.error_text)

    def isError(self):
        return self.error_text

    def status(self, text="Ready", color="blue"):
        self.window.Element("Status").Update(text,   text_color=color)
        self.window.Element('-STATUS-').Update(text, text_color=color)
        logger.info(text)
        return True

    def statusDoing(self, text="Doing ..."):
        self.cursor("circle")
        return self.status(text, color="orange")

    def statusDone(self, text="Done."):
        self.cursor("arrow")
        if (self.isError()) : return True
        return self.status(text, color="green")

    def statusReady(self, text="Ready"):
        self.cursor("arrow")
        if (self.isError()) : return True
        return self.status(text, color="blue")

    def statusError(self, text="Error"):
        self.cursor("arrow")
        # text = text + " : " + self.error_text
        self.error_text = text
        return self.status(text, color="red")

    @staticmethod
    def listToJsonText(text, value="Missing") -> str:
        the_list = text.strip('[]\n"').replace('"', '').replace(' ', '').replace('\'', '').split(',')
        the_dict = dict()
        for elem in the_list:
            if (elem == ""): continue
            the_dict[elem] = str(value)
        the_text = json.dumps(the_dict, indent=4)
        return the_text

    @staticmethod
    def textToJsonText(text) -> str:
        try:
            the_dict = json.loads(text)
        except Exception as e:
            logger.error(str(e))
            return text
        the_text = json.dumps(the_dict, indent=2)
        return the_text

    @staticmethod
    def quotedTextToText(text) -> str:
        if (text[0] == '"') :
            text = text[1:]
        if (text[len(text) - 1] == '"') :
            text = text[:len(text) - 1]
        if (text[len(text) - 2] == '"'):
            text = text[:len(text) - 2]
        the_text = text.replace('\\\"', '\"')
        return the_text

    def checkJsonWidget(self, widget) -> bool:
        if ("/" not in widget):
            widget = self.Resources + "/" + widget
        if (not self.hasWidget(widget)):
            return True
        if (widget not in self.current_values):
            return True
        if (self.checkJson(self.current_values[widget])):
            return True
        self.error("Not a Valid JSON : " + widget)
        return False

    def checkJson(self, text) -> bool:
        if (text == None): return True
        text = text.strip()
        if (text == ""):   return True
        if (text.startswith("(Select")):    return True
        if (text.startswith("( < Select")): return True
        try:
            the_dict = json.loads(text)
            if (the_dict): return True
            return False
        except Exception as e:
            self.error("checkJson : "+str(e))
            return False

    ###
    ### Common
    ###

    def setResource(self, Resource):
        if (Resource == None) or (Resource == ""):
            self.Resource  = None
            self.Resources = None
            self.resources = None
            return
        self.aep_service = re.sub(" .*$", "", self.current_event)
        self.aep_store   = re.sub("^.. ", "", self.current_event)
        self.aep_store   = re.sub("/.*$", "", self.aep_store)
        if (Resource.endswith("ies")):
            self.Resource = re.sub("ies$", "y", self.Resource)
        if (Resource.endswith("s")):
            self.Resource = re.sub("s$", "", Resource)
        if (self.Resource.endswith("ies")):
            self.Resources = re.sub("y$", "ies", self.Resource)
        else:
            self.Resources = self.Resource + "s"
        self.resources = self.Resources.lower()

    def handleOutput(self, event : str, command : str, result : str, payload : str = ""):
        self.last_output = result
        output = self.last_output  # self.quotedTextToText(self.last_output)
        resource = re.sub("/.*$","",event)
        resource = re.sub("^.. ","",resource)
        if (self.output_popup):
            output_data = ut.loadDataContent(output)
            if ((output_data) and isinstance(output_data, dict)):
                # name = str(resource).lower() + " " + str(idName)
                utg.dataBrowserForm(data=output_data, name=str(resource),
                                    formats_choices=["Json", "Yaml", "Flat"], read_only=True, style="TREE",
                                    index_prefix=resource + " ").run()
            else:
                sg.PopupScrolled(output, title=event + " : " + "aepctl " + command, size=(80, 30))
        logger.info("\nEvent : " + event + "\nCommand : " + command + "\nPayload : " + payload + "\nOutput : \n" + str(output))

    def hasWidget(self, widget):
        if ("/" not in widget):
            widget = self.Resources + "/" + widget
        if (widget in self.current_values.keys()):
            return True
        return False

    def getWidgetValue(self, widget, default=None):
        if ("/" not in widget):
            widget = self.Resources + "/" + widget
        if (widget not in self.current_values.keys()):
            return default
        val = self.current_values[widget]
        if (isinstance(val, str)):
            return self.current_values[widget]
        else:  # A set with a single row
            if (len(self.current_values[widget]) != 0):
                return self.current_values[widget][0]
            else:
                return default

    def setWidgetValue(self, widget, value):
        if ("/" not in widget):
            widget = self.Resources + "/" + widget
        if (widget not in self.current_values.keys()):
            logger.error("Set : No such Widget : " + widget)
            return None
        self.udata[widget] = value
        if (widget not in self.current_values.keys()):
            logger.error("Set : No such Widget : " + widget)
            return None
        sub = re.sub("^.*/", "", widget)
        if (sub == "Text") or (sub == "Output") or (sub == "Context"):
            if (not value.startswith("( <")):
                value = self.textToJsonText(value)
        self.window.Element(widget).Update(value)
        self.udata[widget] = value
        return value

    def clearAepList(self):
        self.setWidgetValue(self.Resources + "/Listing", [ "(Click List)" , ""  ])

    def updateAepList(self, aep_list, listOnly=False):
        item_list = ut.loadDataContent(aep_list)
        if (listOnly == True): return
        self.clearAepEntry()
        if (len(item_list) != 0):
            self.setWidgetValue(self.Resources + "/Listing", item_list)
        else :
            self.setWidgetValue(self.Resources + "/Listing", ["-Empty-"])
        self.setWidgetValue("Text",   "( < Select "+self.Resource+")")

    def updateAepEntry(self, entry : str , what : str = None):  # , version=True):
        if (what == None):
            self.current_element = self.getWidgetValue(self.Resources + "/Name")
        else:
            self.current_element = what
        obj      = ut.loadDataContent(entry)
        id_att   = aep.StoreManager.get_id_att(str(self.Resources))
        name_att = aep.StoreManager.get_name_att(str(self.Resources))
        desc_att = aep.StoreManager.get_desc_att(str(self.Resources))
        if ((not obj) or (id_att not in obj)):
            ident = "(No identifier found)"
            self.setWidgetValue(self.Resources + "/Name",        str(what))
            self.setWidgetValue(self.Resources + "/Identifier",  str(ident))
            self.setWidgetValue(self.Resources + "/Description", str(aep.StoreManager.get_description(str(self.Resources), str(ident))))
            self.setWidgetValue(self.Resources + "/Text",        str(entry))
        else:
            self.setWidgetValue(self.Resources + "/Name",        str(obj[name_att]))
            self.setWidgetValue(self.Resources + "/Identifier",  str(obj[id_att]))
            self.setWidgetValue(self.Resources + "/Description", str(obj[desc_att]))
            self.setWidgetValue(self.Resources + "/Text",        str(entry))

    def newAepEntry(self, entry):
        self.setWidgetValue("Name", "")
        self.setWidgetValue("Description", "Edit New Entry")
        self.setWidgetValue("Identifier", "")
        newObject = aep.StoreManager.get_template(self.Resource)
        if (not newObject):
            text = "No Schema for " + self.Resource
        else:
            text = ut.to_json(newObject)
        self.setWidgetValue("Text", entry)

    def clearAepEntry(self, output=True):
        self.setWidgetValue("Name",         "")
        self.setWidgetValue("Description",  "")
        self.setWidgetValue("Identifier",   "")
        self.setWidgetValue("Text",         "( < Select "+self.Resource+")")

    def updateWso2Entry(self, entry : str , what : str = None):  # , version=True):
        if (what == None):
            self.current_element = self.getWidgetValue(self.Resources + "/Name")
        else:
            self.current_element = what
        obj = ut.loadDataContent(entry)
        if ("role" in obj):  # WS Users
            self.setWidgetValue(self.Resources + "/Name",        str(obj["name"]))
            self.setWidgetValue(self.Resources + "/Identifier",  str(obj["name"]))
            self.setWidgetValue(self.Resources + "/Description", str(obj["role"]))
            self.setWidgetValue(self.Resources + "/Text",        str(entry))
            return

        id_att   = aep.StoreManager.get_id_att(str(self.Resources))
        name_att = aep.StoreManager.get_name_att(str(self.Resources))
        desc_att = aep.StoreManager.get_desc_att(str(self.Resources))
        if ((not obj) or (id_att not in obj)):
            ident = "(No identifier found)"
            self.setWidgetValue(self.Resources + "/Name",        str(what))
            self.setWidgetValue(self.Resources + "/Identifier",  str(ident))
            self.setWidgetValue(self.Resources + "/Description", str(aep.StoreManager.get_description(str(self.Resources), str(ident))))
            self.setWidgetValue(self.Resources + "/Text",        str(entry))
        else:
            self.setWidgetValue(self.Resources + "/Name",        str(obj[name_att]))
            self.setWidgetValue(self.Resources + "/Identifier",  str(obj[id_att]))
            self.setWidgetValue(self.Resources + "/Description", str(obj[desc_att]))
            self.setWidgetValue(self.Resources + "/Text",        str(entry))

    ###
    ### System
    ###

    ###
    def handleSystemRequest(self, request) -> bool:
        """
        try:
            self.restRequest(request)
            self.setWidgetValue("System/Output", self.reqServer.r_text)
            return self.reqServer.isError()
        except Exception as e:
            self.setWidgetValue("System/Output", str(e))
            self.error(str(e))
            return False
        """
        return (self == request)  # Shutup Code Checker

    ###
    def handleSystemEvent(self, event):

        # Not Implemented
        if (event == "System/SystemBt"):
            return self.handleSystemRequest("help/sys")

        if (event == "System/SystemLogsBt"):
            return self.handleSystemRequest("help/logs")

        if (event == "System/SystemErrorsBt"):
            return self.handleSystemRequest("help/errors")

        if (event == "System/ClusterLogsBt"):
            return self.handleSystemRequest("help/cluster")

        if (event == "System/ClusterErrorsBt"):
            return self.handleSystemRequest("help/cluster_errors")

        if (event == "System/UsersBt"):
            return self.handleSystemRequest("help/users")

        if (event == "System/ResetBt"):
            self.setWidgetValue("Output", "System Reset : Will be back in a few seconds ... ")
            self.status("System Reset : Will be back in a few seconds ... ", "orange")
            return self.handleSystemRequest("help/reset")

        if (event == "System/HelpBt"):
            return self.handleSystemRequest("help/help")

        if (event == "System/RequestsBt"):
            return self.handleSystemRequest("help/requests")

        if (event == "System/EnvironmentBt"):
            return self.handleSystemRequest("help/env")

        if (event == "System/OperationsAPIBt"):
            return self.handleSystemRequest("help/ANME_Operations_OpenApi")

        if (event == "System/TrafficAPIBt"):
            return self.handleSystemRequest("help/ANME_Traffic_OpenApi")

        if (event == "System/NotificationsAPIBt"):
            return self.handleSystemRequest("help/ANME_Triggering_OpenApi")

    ###
    ### AEP CTL DataStores
    ###

    def eventResource(self, event) -> str:
        self.aep_service = self.aep_service
        resource = event
        if ("/" in event):
            resource = re.sub("/.*$", "", resource)
        return resource

    def eventWidget(self, event) -> str:
        if ("/" in event):
            return re.sub("^.*/", "", self.current_event)
        else:
            return event

    def checkPayload(self, payload : str) -> Union[dict, None] :
        self.error(None)
        try :
            payload = json.loads(payload)
        except Exception as err:
            self.error("checkPayload json error : " + str(err))
            return None
        if (self.aep_service.lower() == "ws"):
            entity_name = "ws_"+self.aep_store
        else:
            entity_name = self.aep_store
        res = aep.StoreManager().check_schema(payload, entity_name)
        if (res) :
            self.error("checkPayload schema error : " + str(res))
            return None
        return payload

    def aepctl(self, command, event="Unkown"):
        global aep_debug
        self.aepctl_last_command = ""
        self.aepctl_last_result  = ""
        command = aep_debug + command
        logger.info("aepctl command : " + command)
        self.aepctl_last_command = command
        self.error(None)
        self.cursor("wait")
        ut.Term.print_yellow("aepctl " +command)
        res = aep.main(command, interactive=False)
        self.aepctl_last_result  = str(res)
        if (res == None) :
            self.error("aepctl : returned " + str(res))
            self.handleOutput(event=event, command=command, result="None - Error or Invalid Command")
            return res
        if (not (res.strip().startswith("{") or res.strip().startswith("["))):
            if (not ut.to_yaml(res)):
                self.error(res)
            if (len(res.splitlines()) <= 2):
                self.error(res)
        self.handleOutput(event=event, command=command, result=res)
        return res

    def loadList(self, event):
        resource = self.eventResource(event)
        cmd = resource + " list names"
        res = self.aepctl(cmd, event)
        if self.isError():
            return False
        self.updateAepList(res)
        self.setWidgetValue("Text", res)
        return True

    def loadEntry(self, event, entry_id : str = None):
        resource = self.eventResource(event)
        if (not entry_id) :
            if (len(self.current_values[resource + "/Listing"]) == 0):
                return False
            entry_id = self.current_values[resource + "/Listing"][0]
        cmd = resource + " get " + entry_id
        res = self.aepctl(cmd, event)
        if self.isError():
            return False
        if (event.startswith("WS")) :
            self.updateWso2Entry(res, entry_id)
        else:
            self.updateAepEntry(res, entry_id)
        # self.setWidgetValue("Output", res)
        return True

    def deleteResource(self, event, entry_id : str = None):
        resource = self.eventResource(event)
        if (not entry_id) :
            entry_id = self.current_values[resource + "/Listing"][0]
        cmd = resource + " delete " + entry_id
        res = self.aepctl(cmd, event)
        if self.isError():
            return False
        self.updateAepEntry(res, entry_id)
        self.clearAepEntry(output=False)
        self.loadList(event)
        return True

    def saveResource(self, event, entry_id : str = None):
        resource = self.eventResource(event)
        if (not entry_id) :
            entry_id = self.current_values[resource + "/Listing"][0]
        payload  = self.getWidgetValue(self.Resources + "/Text")
        self.checkPayload(payload)
        if self.isError():
            return False
        file_payload = ".tmp_payload.json"
        ut.saveFileContent(payload, file_payload, safe=False)
        cmd = resource + " update -p " + file_payload
        res = self.aepctl(cmd, event)
        if self.isError():
            return False
        self.updateAepEntry(res, entry_id)
        # self.setWidgetValue("Output", res)
        self.clearAepEntry(output=False)
        self.loadList(event)
        return True

    def backupResource(self, resource):
        self.Resource = resource
        event = self.Resource + "/BackUp"
        self.statusDoing(event + " - BackUp " + self.Resource + " ...")
        bupdir = utg.directorySelectorForm(buttonName="BackUp", windowTitle="Select BackUp Directory")
        if (not bupdir): return False
        cmd = self.Resource + " backUp " + bupdir
        res = self.aepctl(cmd, self.Resource + "/backUp")
        # self.setWidgetValue("Output", res)
        self.statusDone("BackedUp " + self.Resource + ".")
        return True

    def loadDataSet(self, resource):
        self.Resource = resource
        event = self.Resource + "/LoadDataSet"
        self.statusDoing(event + " - Load DataSet " + self.Resource + " ...")
        loadPath = utg.fileDirectorySelectorForm(buttonName="Load", windowTitle="Select Load Data Set")
        if (not loadPath): return False
        cmd = self.Resource + " load " + loadPath
        res = self.aepctl(cmd, self.Resource + "/LoadDataSet")
        self.setWidgetValue(self.Resources + "/Text", str(res))
        self.statusDone("Loaded DataSet " + self.Resource + ".")
        return True

    def deleteAll(self, service : str = "FS"):
        self.statusError("deleteAll DataSet " + service + " : Not Implemented.")
        self.statusDoing("Deleting All " + service )
        if (sg.PopupYesNo("Delete All " + service + " ?", title="Delete All ?") != "Yes"): return True
        cmd = service + " delete_all "
        res = self.aepctl(cmd)
        if self.isError():
            return False
        self.clearAepList()
        self.setWidgetValue(self.Resources + "/Text", str(res))
        return self.statusDone("Deleted All " + service + ".")

    def copyStore(self, serviceFrom : str = "FS", serviceTo : str = "DS"):
        self.statusError("copyStore From " + serviceFrom + " To " + serviceTo + " : Not Implemented.")
        self.statusDoing("copyStore From " + serviceFrom + " To " + serviceTo + " ...")
        if (sg.PopupYesNo("Copy Store " + serviceFrom + " to " + serviceTo + " ?", title="Delete All ?") != "Yes"): return True
        cmd = serviceFrom + " export  " + serviceTo
        res = self.aepctl(cmd)
        if self.isError():
            return False
        self.clearAepList()
        self.setWidgetValue(self.Resources + "/Text", str(res))
        return self.statusDone("copied Store From " + serviceFrom + " To " + serviceTo + " ...")
        return True

    def backupWS(self):
        self.statusError("backupWS" + " : Not Implemented.")
        return True

    def provisionWS(self, serviceFrom : str = "FS"):
        self.statusError("provisionWS From " + serviceFrom + " : Not Implemented.")
        return True

    def extractWS(self, serviceTo : str = "FS"):
        self.statusError("extractWS To " + serviceTo + " : Not Implemented.")
        return True

    def templateResource(self, event):
        resource = self.eventResource(event)
        cmd = resource + " template json"
        res = self.aepctl(cmd, event)
        if self.isError():
            return False
        self.newAepEntry(res)
        return True

    def handleAepEvent(self, event):

        widget   = self.eventWidget(event)

        if ("Tabs" in widget):  # Tab Focus
            self.loadList(self.current_value)
            return True

        if (widget == "Listing"):  # Load List
            if (self.current_value[0] in ["(Click List)", "-Empty-"]):
                self.loadList(event)
                return self.statusDone("Listed " + self.Resource + ".")
            else:
                self.loadEntry(event)
                return self.statusDone("Loaded " + self.Resource + " " + self.current_element + ".")

        if (widget == "ListBt"):  # Load List
            self.loadList(event)
            return self.statusDone("Listed "+self.Resource+".")

        if (widget == "DeleteBt"):
            entity     = self.Resources
            entry      = self.getWidgetValue(entity + "/Text")
            dentry     = self.checkPayload(entry)
            if (self.isError()): return True
            name       = dentry[aep.StoreManager().get_name_att(entity=entity)]
            self.statusDoing("Deleting " + entity + " [" + name + "] ...")
            if (sg.PopupYesNo("Delete "  + entity + " [" + name + "] ?", title="Delete ?") != "Yes"): return True
            self.deleteResource(entity, name)
            return self.statusDone("Deleted "+entity+".")

        if (widget == "SaveBt"):
            entity     = self.Resources
            entry      = self.getWidgetValue(entity + "/Text")
            dentry     = self.checkPayload(entry)
            if (self.isError()): return True
            name       = dentry[aep.StoreManager().get_name_att(entity=entity)]
            self.statusDoing("Saving " + entity + " [" + name + "] ...")
            if (sg.PopupYesNo("Save "  + entity + " as [" + name + "] ?", title="Save ?") != "Yes"): return True
            self.saveResource(entity, entry)
            return self.statusDone("Saved "+entity+" ["+name+"]")

        if (widget == "CheckBt"):
            entity     = self.Resources
            entry      = self.getWidgetValue(entity + "/Text")
            self.checkPayload(entry)
            self.statusDoing("Check " + entity + " ...")
            if (self.isError()):
                sg.PopupScrolled(self.error_text, title="Check Error : ", size=(60, 20))
                return self.statusError("Check Error")
            else:
                return self.statusDone("Check OK")

        if (widget == "ClearBt"):
            self.statusDoing("Clear "+self.Resource+" ...")
            self.clearAepEntry()
            self.loadList(event)
            return self.statusDone("Cleared "+self.Resource+".")

        if (widget == "NewBt"):
            self.statusDoing("New "+self.Resource+" ...")
            self.templateResource(event)
            return self.statusDone("Newed "+self.Resource+".")

        if (widget == "LoadBt") :
            entity     = self.Resources
            self.statusDoing("Load "+entity+" ...")
            self.loadEntry(event, self.getWidgetValue("Name"))
            return self.statusDone("Loaded "+entity+".")

        if (widget == "SchemaBt"):
            entity     = self.Resources
            self.statusDoing("Schema "+entity+" ...")
            cmd = self.eventResource(event) + " schema "
            res = self.aepctl(cmd, event)
            self.setWidgetValue(entity + "/Text", str(res))
            return self.statusDone("Schema "+entity+".")

        if (widget == "OpenAPIBt"):
            self.statusDoing("OpenAPI "+self.Resource+" ...")
            cmd = self.eventResource(event) + " openapi "
            res = self.aepctl(cmd, event)
            self.setWidgetValue(self.Resources + "/Text",        str(res))
            return self.statusDone("OpenAPI "+self.Resource+".")

        if (widget == "BackUpBt"):
            self.statusDoing("BackUp "+self.Resource+" ...")
            if (sg.PopupYesNo("BackUp " + self.Resource + " ?", title="BackUp ?") != "Yes"): return True
            cmd = self.eventResource(event) + " backUp "
            res = self.aepctl(cmd, event)
            self.setWidgetValue(self.Resources + "/Text",        str(res))
            return self.statusDone("BackedUp "+self.Resource+".")

        if (widget == "EditBt"):
            self.statusDoing("Editing "+self.Resource+" ...")
            self.loadEntry(event=event)
            content = self.getWidgetValue("Text", "NO_TEXT")
            self.openFile(content, self.Resources, self.current_element)
            return self.statusDone("Edit "+self.Resource+".")

        if (widget == "ProvisionBt"):
            self.statusDoing("Provisioning "+self.Resource+" ...")
            self.loadEntry(event=event)
            cmd = self.eventResource(event) + " provision " + self.getWidgetValue("Name")
            res = self.aepctl(cmd, event)
            self.setWidgetValue(self.Resources + "/Text",        str(res))
            return self.statusDone("Provisioned "+self.Resource+".")

    def handleWso2Event(self, event):

        widget   = self.eventWidget(event)

        if ("Tabs" in widget):  # Tab Focus
            self.loadList(self.current_value)
            return True

        if (widget == "ListBt"):  # Load List
            self.loadList(event)
            return self.statusDone("Listed "+self.Resource+".")

        if (widget == "Listing"):  # Load Entry in List, or List if Empty
            if (self.current_value[0] in ["(Click List)", "-Empty-"]):
                self.loadList(event)
                return self.statusDone("Listed " + self.Resource + ".")
            else:
                self.loadEntry(event)
                return self.statusDone("Loaded " + self.Resource + " " + self.current_element + ".")

        if (widget == "DeleteBt"):
            self.checkPayload(self.getWidgetValue(self.Resources + "/Text"))
            if (self.isError()): return True
            self.statusDoing("Deleting "+self.Resource+" ...")
            entry    = self.getWidgetValue(self.Resources + "/Text")
            dentry   = json.loads(entry)
            name_att = aep.StoreManager().get_name_att(entity=self.Resources)
            name     = dentry[name_att]
            if (sg.PopupYesNo("Delete " + self.Resource + " [" + name + "] ?", title="Delete ?") != "Yes"): return True
            self.deleteResource(self.Resources, name)
            return self.statusDone("Deleted "+self.Resource+".")

        if (widget == "SaveBt"):
            if (widget == "SaveBt"):
                self.statusError("No Save for Wso2 : Use Provisionning instead.")
                return True
            self.checkPayload(self.getWidgetValue(self.Resources + "/Text"))
            if (self.isError()): return True
            self.statusDoing("Saving "+self.Resource+" ...")
            entry    = self.getWidgetValue(self.Resources + "/Text")
            dentry   = json.loads(entry)
            if ((dentry == None) or (not isinstance(dentry,dict))):
                self.statusError("Invalid  Entry Selected")
                return True
            name_att = aep.StoreManager().get_name_att(entity=self.Resources)
            name = dentry[name_att]
            if (sg.PopupYesNo("Save " + self.Resource + " as [" + name + "] ?", title="Save ?") != "Yes"): return True
            self.saveResource(self.Resources, entry)
            return self.statusDone("Saved "+self.Resource+" ["+name+"]")

        if (widget == "CheckBt"):
            self.statusDoing("Check "+self.Resource+" ...")
            self.checkPayload(self.getWidgetValue(self.Resources + "/Text"))

            if (self.isError()):
                sg.PopupScrolled(self.error_text, title="Check Error : ", size=(60, 20))
                return self.statusError("Check Error")
            else:
                return self.statusDone("Check OK")

        if (widget == "ClearBt"):
            self.statusDoing("Clear "+self.Resource+" ...")
            self.clearAepEntry()
            self.loadList(event)
            return self.statusDone("Cleared "+self.Resource+".")

        if (widget == "LoadBt") :
            name = self.getWidgetValue("Name")
            if ((name == None) or (name.strip() == "")):
                self.statusError("Invalid  Entry Selected")
                return True
            self.statusDoing("Load "+self.Resource+" ...")
            self.loadEntry(event, self.getWidgetValue("Name"))
            return self.statusDone("Load "+self.Resource+".")

        if (widget == "SchemaBt"):
            self.statusError("No Schema for Wso2")
            return True

        if (widget == "OpenAPIBt"):
            name = self.getWidgetValue("Name")
            if ((name == None) or (name.strip() == "")):
                self.statusError("Invalid  Entry Selected")
                return True
            self.statusDoing("OpenAPI "+self.Resource+" ...")
            cmd = self.eventResource(event) + " openapi " + name
            res = self.aepctl(cmd, event)
            self.setWidgetValue(self.Resources + "/Text",        str(res))
            return self.statusDone("OpenAPI "+self.Resource+".")

        if (widget == "BackUpBt"):
            self.statusDoing("BackUp "+self.Resource+" ...")
            if (sg.PopupYesNo("BackUp " + self.Resource + " ?", title="BackUp ?") != "Yes"): return True
            cmd = self.eventResource(event) + " backUp "
            res = self.aepctl(cmd, event)
            self.setWidgetValue(self.Resources + "/Text",        str(res))
            return self.statusDone("BackedUp "+self.Resource+".")

        if (widget == "EditBt"):
            name = self.getWidgetValue("Name")
            if ((name == None) or (name.strip() == "")):
                self.statusError("Invalid  Entry Selected")
                return True
            self.statusDoing("Editing "+self.Resource+" ...")
            self.loadEntry(event)
            content = self.getWidgetValue("Text", "NO_TEXT")
            self.openFile(content, self.Resources, self.current_element)
            return self.statusDone("Edit "+self.Resource+".")

        if (widget == "DetailsBt"):
            name = self.getWidgetValue("Name")
            if ((name == None) or (name.strip() == "")):
                self.statusError("Invalid  Entry Selected")
                return True
            self.statusDoing("Details "+self.Resource+" ...")
            cmd = self.eventResource(event) + " details " + name
            res = self.aepctl(cmd, event)
            self.setWidgetValue(self.Resources + "/Text",        str(res))
            return self.statusDone("Details "+self.Resource+".")

        if (widget == "ThumbnailBt"):
            name = self.getWidgetValue("Name")
            if ((name == None) or (name.strip() == "")):
                self.statusError("Invalid  Entry Selected")
                return True
            self.statusDoing("Thumbnail "+self.Resource+" ...")
            cmd = self.eventResource(event) + " thumbnail " + name
            res = self.aepctl(cmd, event)
            self.setWidgetValue(self.Resources + "/Text",        str(res))
            return self.statusDone("Thumbnail "+self.Resource+".")

    ###
    ### Main
    ###

    def initWindow(self):
        self.window    = None
        self.udata     = ut.SuperDict().clean()
        self.runTime   = ut.SuperDict(name="RunTime Data")
        self.current_tab      = ""
        self.current_list     = ()
        self.current_element  = ""
        self.current_content  = ""
        self.current_content_file = None
        self.current_content_ext  = ""
        self.current_action   = ""
        self.current_event    = ""
        self.current_values   = ""
        self.Resource         = ""
        self.Resources        = ""
        self.resources        = ""
        self.error_text    = None
        self.no_refresh    = True
        self.output_popup  = False
        self.last_output   = ""
        self.theme         = utg.settingsForm.getSettings(application=application_settings, item="Theme")
        self.editor        = utg.settingsForm.getSettings(application=application_settings, item="Editor")
        sg.theme(self.theme)

    def cursor(self, cursor):
        if (sys.platform != 'cygwin'):
            self.window.set_cursor(cursor)
        return

    def logEvent(self, what=None):
        if (what == None):
            if (self.current_event == "System/Timeout"):
                logger.debug("Event   : " + str(self.current_event) + " - " + str(refresh_timeout) + " ms")
            else:
                logger.info( "Event   : " + str(self.current_event))
            return
        if (what == "Event"):
            logger.info("Event   : " + str(self.current_event))
            logger.info("Values  : " + json.dumps(self.current_values, indent=2))
            logger.info("Event   : " + str(self.current_event))
            logger.info("RunTime : " + json.dumps(self.runTime.getAsData(), indent=2))
            logger.info("Event   : " + str(self.current_event))
        if (what == "Details"):
            logger.info("current_event        : " + str(self.current_event))
            logger.info("current_tab          : " + str(self.current_tab))
            logger.info("current_list         : " + str(self.current_list))
            logger.info("current_element      : " + str(self.current_element))
            logger.info("current_content_file : " + str(self.current_content_file))
            logger.info("current_content_ext  : " + str(self.current_content_ext))
            logger.info("current_action       : " + str(self.current_action))
            logger.info("current_value        : " + str(self.current_value))
            logger.info("Resource             : " + str(self.Resource))
            logger.info("Resources            : " + str(self.Resources))
            logger.info("resources            : " + str(self.resources))
            logger.info("output_popup         : " + str(self.output_popup))
        if (what == "Content") or (what == "Text") or (what == what == "Input"):
            logger.info("current_content      : " + str(self.current_event))
            logger.info("current_content_file : " + str(self.current_event))
            logger.info("current_content_ext  : " + str(self.current_event))
        if (what == "Status") or (what == "Error"):
            logger.info("error   (red) : " + str(self.error_text))

    def collectEvent(self, event, values):
        self.no_refresh     = False
        self.current_event  = event
        self.current_values = values
        self.udata          = ut.SuperDict().clean()
        if ("/" in self.current_event):
            self.current_tab    = re.sub("/.*$", "", self.current_event)
            self.current_widget = re.sub("^.*/", "", self.current_event)
        else:
            self.current_tab    = self.current_event
            self.current_widget = self.current_event
        self.current_action = self.current_widget.replace("Bt", "")
        self.current_action = self.current_action.replace("Tab", "")
        if (self.Resources + "/Text" in self.current_values.keys()):
            self.current_content = values[self.Resources + "/Text"]
        else:
            self.current_content = None
        if (self.current_content_ext == None):
            if (self.current_tab in extensionsSettings["Extensions"].keys()):
                self.current_content_ext = extensionsSettings["Extensions"][self.current_tab]
        self.setResource(self.current_tab)
        if (self.Resources) and (self.Resources + "/Name" in self.current_values.keys()):
            self.current_element = self.current_values[self.Resources + "/Name"]
        else:
            self.current_element = None
        if (self.Resources) and (self.Resources + "/List" in self.current_values.keys()):
            self.current_list = self.current_values[self.Resources + "/List"]
        else:
            self.current_list = ()
        if (self.current_event in self.current_values.keys()):
            self.current_value = self.current_values[self.current_event]
        else:
            self.current_value = None
        self.error_text    = None


    ###
    def refreshFile(self):
        if (self.Resources == None) or (self.Resources == "") or (self.current_element == None) or (self.current_element == ""):
            return False
        res  = self.current_tab
        name = self.current_element
        if (self.Resources in extensionsSettings["Extensions"].keys()):
            extension = extensionsSettings["Extensions"][self.current_tab]
        else:
            extension = 'json'
        filepath = tempfile.gettempdir() + os.sep + res + "_" + name + "." + extension
        if (not ut.safeFileExist(filepath)): return False
        tt = str(os.stat(filepath).st_mtime)
        if (tt == self.runTime["TimeStamps/"+filepath]):
            return False
        # Reload File
        text = ut.loadFileContent(filepath)
        self.current_values[res+"/Text"] = text
        if (res+"/"+name in self.current_values.keys()):
            self.window.Element(res+"/"+name).Update(value=str(text))
            return
        if (res+"/Text" in self.current_values.keys()):
            self.window.Element(res+"/Text").Update(value=str(text))
        if (res+"/Input" in self.current_values.keys()):
            self.window.Element(res+"/Input").Update(value=str(text))
        self.runTime["TimeStamps/" + filepath] = tt
        return True

    ###
    def openFile(self, text, res, name):
        if ((not self.current_content_ext) or (self.current_content_ext == "")):
            if (self.current_tab not in extensionsSettings["Extensions"]) :
                self.current_content_ext = 'json'
            else:
                logger.info("No Extension defined in extensionsSettings for : " + self.Resources)
                self.current_content_ext = extensionsSettings["Extensions"][self.current_tab]
        filepath = tempfile.gettempdir() + os.sep + res + "_" + name + "." + str(self.current_content_ext)
        logger.info("Opening file : " + filepath)
        ut.saveFileContent(text, filepath)
        # os.remove(filepath)
        if platform.system() == 'Darwin':  # macOS
            subprocess.call(('open', filepath))
        elif platform.system() == 'Windows':  # Windows
            os.startfile(filepath)
            # os.startfile(filepath,"edit")
        else:  # linux variants
            subprocess.call(('xdg-open', filepath))
        self.runTime["TimeStamps/"+filepath] = str(os.stat(filepath).st_mtime)
        return filepath

    def refreshWidgets(self):
        if (self.no_refresh) : return
        if (self.current_tab == "Tabs"):
            self.current_tab = self.current_action
            self.current_element = ""
            self.current_action  = "Focus"
        title = application
        if (self.current_event == None) : return
        if (self.current_tab != None)     and (self.current_tab != "")     : title = self.current_tab
        if (self.current_element != None) and (self.current_element != "") : title =  title + " : [" + self.current_element + "]"
        if (self.current_action != None)  and (self.current_action != "")  : title =  title + " - " + self.current_action
        if (self.aepctl_last_command != None)  and (self.aepctl_last_command != "")  : title =  "aepctl" + " " + self.aepctl_last_command
        if (self.current_tab != "") :
            self.udata[self.current_tab+"/Title"] = title

        # Refresh Widgets with Updated Values
        self.refreshFile()
        fuData = ut.flatten(self.udata.getAsData(), "/")
        logger.info(fuData)
        for uKey in fuData.keys():
            logger.info(uKey)
            if (uKey in self.current_values):
                if (str(self.udata[uKey]) != str(self.current_values[uKey])):
                    self.window.Element(uKey).Update(self.udata[uKey])
            logger.info(uKey)
            if ("Title" in uKey) and ("DS_" not in uKey) and ("FS_" not in uKey) and ("WS_" not in uKey):
                self.window.Element(uKey).Update(self.udata[uKey])
        """
        # Rest Message
        if (self.reqServer.r_code == 0):
            self.window.Element("Status").Update(self.message , text_color=self.message_color)
            self.status(self.message, self.message_color)
        else:
            summary = self.reqServer.summary()
            if (self.reqServer.r_code < 299):
                self.window.Element("Status").Update(summary , text_color="green")
                self.status(summary , "green")
            else:
                self.error(self.reqServer.r_text)
                self.error(summary)
                self.status(summary , "red")
                self.window.Element("Status").Update(summary , text_color="red")
            if (self.Resources+"/Rest" in self.current_values):
                self.window.Element(self.Resources+"/Rest").Update(self.reqServer.getLogs(reset=True))
        """

    def run(self, debug : bool = False):
        global aep_debug

        if (debug):
            aep_debug = "-v "
            ut.Verbose.init_verbose(True)
        else:
            aep_debug = ""
            ut.Verbose.init_verbose(False)

        sg.theme(utg.settingsForm.getSettings(application=application_settings, item="Theme"))
        self.window = sg.Window(application, Layout.createMainLayout(), default_element_size=(80, 1), grab_anywhere=False, resizable=False)

        # Initial Inits
        initDone = False

        # The Event Loop
        while True:
            self.refreshWidgets()
            if (self.current_event != "System/Timeout"):
                logger.info("Event   : " + str(self.current_event) + " - " + str("Done"))
            if (initDone): self.cursor("arrow")
            self.current_event, self.current_values = self.window.Read(timeout=refresh_timeout, timeout_key="System/Timeout")  # in ms
            if (initDone): self.cursor("circle")
            if (self.current_event is None): break
            self.no_refresh = False
            self.logEvent()

            # System Event Processing
            if (self.current_event == "System/Timeout"):
                # logger.info("System/Timeout")
                self.no_refresh = True
                if (initDone == False):
                    # Initial Inits
                    initDone = True
                self.refreshFile()
                continue

            # Exit
            if ((self.current_event == "Exit") or ('M_EXIT' in self.current_event)):
                self.status("Exit ...")
                self.window.close()
                return

            # Ignore Some Tabs Events
            if ("Tabs" in self.current_event):
                tab = self.current_values["Tabs"]
                logger.info("# Tab Focus Change : " + tab)
                logger.info("Ignored Event : "+self.current_event)
                # self.current_event  = "Tabs/"+tab
                # self.status(text=self.current_event, color="grey")
                # self.window.Element(widget).Update(values=self.current_relist)
                continue

            ###
            ### Menu Events
            ###

            # About
            if (self.current_event == 'About ...') or ('M_ABOUT' in self.current_event):
                utg.aboutPopup(configuration_file=utg.settingsForm.getSettingsFile())
                continue

            # Last Error
            if (self.current_event == "Error ...") or ('M_ERROR' in self.current_event):  # Show Last Error
                self.current_event  = "System/Error"
                self.status("Last Error", "red")
                self.logEvent("Error")
                sg.PopupScrolled(self.error_text, title="Last Error :", size=(60, 20))
                continue

            # Edit Settings
            if (self.current_event == 'Theme, Editor ...') or ('M_SETTINGS' in self.current_event):
                self.status("Edit Settings")
                utg.settingsForm.editSettings(application=application_settings, no_server=True)
                sg.theme(utg.settingsForm.getSettings(application=application_settings, item="Theme"))
                continue

            # Toggle Output Popup
            if (self.current_event == 'Toggle Output') or ('M_TOGGLE_OUTPUT' in self.current_event):
                self.output_popup = not self.output_popup
                self.statusDone("Toggled Output")
                continue

            # Verbose ON/OFF
            if (self.current_event == 'Toggle Debug') or ('M_DEBUG' in self.current_event):
                if (aep_debug == ""):
                    aep_debug = "-v "
                    ut.Verbose.swap_verbose()
                    self.statusDone("Verbose ON")
                else:
                    aep_debug = ""
                    ut.Verbose.swap_verbose()
                    self.statusDone("Verbose OFF")
                continue

            # How to / Help
            if (self.current_event == 'Help ...') or ('M_HELP' in self.current_event):
                res = self.aepctl("help")
                sg.PopupScrolled(res, title="Help on aepctl", size=(40, 20))
                continue

            # Show Configuration
            if (self.current_event == 'Configuration ...') or ('M_CONFIG' in self.current_event):
                res = self.aepctl("help")
                sg.PopupScrolled(res, title="aepctl Configuration", size=(40, 20))
                continue

            # Menu : FS Load / Save / Back Up / Restore
            if ('M_FS' in self.current_event):
                if ('M_FS_BACKUP' in self.current_event):
                    self.backupResource("FS")
                    continue

                if ('M_FS_RESTORE' in self.current_event):
                    self.loadDataSet("FS")
                    continue

                if ('M_FS_DELETE_ALL' in self.current_event):
                    self.deleteAll("FS")
                    continue

                if ('M_FS_LOAD' in self.current_event):
                    self.loadDataSet("FS")
                    continue

                if ('M_FS_EXPORT_DS' in self.current_event):
                    self.copyStore("FS","DS")
                    continue

                if ('M_FS_IMPORT_DS' in self.current_event):
                    self.copyStore("DS","FS")
                    continue

                if ('M_FS_PROVISION_WS' in self.current_event):
                    self.provisionWS("FS")
                    continue

            # Menu : DS Load / Save / Back Up / Restore / ...
            if ('M_DS' in self.current_event):
                if ('M_DS_BACKUP' in self.current_event):
                    self.backupResource("DS")
                    continue

                if ('M_DS_RESTORE' in self.current_event):
                    self.loadDataSet("DS")
                    continue

                if ('M_DS_DELETE_ALL' in self.current_event):
                    self.deleteAll("DS")
                    continue

                if ('M_DS_LOAD' in self.current_event):
                    self.loadDataSet("DS")
                    continue

                if ('M_DS_EXPORT_FS' in self.current_event):
                    self.copyStore("DS","FS")
                    continue

                if ('M_DS_IMPORT_FS' in self.current_event):
                    self.copyStore("FS","DS")
                    continue

                if ('M_DS_PROVISION_WS' in self.current_event):
                    self.provisionWS("DS")
                    continue

            # Menu : WS Load / Save / Back Up / Restore / ...
            if ('M_WS' in self.current_event):
                if ('M_WS_BACKUP' in self.current_event):
                    self.backupWS()
                    continue

                if ('M_WS_PROVISION_FS' in self.current_event):
                    self.provisionWS("FS")
                    continue

                if ('M_WS_PROVISION_DS' in self.current_event):
                    self.provisionWS("DS")
                    continue

                if ('M_WS_EXTRACT_FS' in self.current_event):
                    self.extractWS("FS")
                    continue

                if ('M_WS_EXTRACT_DS' in self.current_event):
                    self.extractWS("DS")
                    continue

            #  Event Processing
            self.logEvent("Event")
            self.collectEvent(self.current_event, self.current_values)
            self.status("OK", color="green")
            self.logEvent("Details")

            if (self.current_event.startswith("WS")) :
                if self.handleWso2Event(self.current_event):      continue
            if self.handleAepEvent(self.current_event):           continue
            if self.handleSystemEvent(self.current_event):        continue
            self.error("===> Widget Event Not Implemented : "+self.current_event+" - "+str(self.current_value))


def start_aepctlui() -> str :
    thread = Thread(target=MainGUI().run())
    thread.setDaemon(True)
    thread.start()
    return "aepctlui"


if __name__ == '__main__':
    logging.basicConfig(format='%(levelname)s:%(name)s:%(message)s', level=logging.INFO)
    MainGUI().run(debug=True)

