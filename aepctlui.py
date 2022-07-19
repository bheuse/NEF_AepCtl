#!/usr/bin/env Python3      
import PySimpleGUI as sg
import subprocess
import platform
import os
import threading
import re
import urllib
import tempfile
import json
import time
import csv
import io
import webbrowser
import logging

import yaml

import Util as ut
import Util_GUI as utg
import aepctl as aep

logging.basicConfig(format='%(levelname)s:%(name)s:%(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

application          = "Amdocs Exposure Platform Management Console"
application_settings = "AEP Control"

aep_debug = "-v "
ut.Verbose.init_verbose(True)
hint_text = "Select Data Store ... >"

refresh_timeout = 200

settings = {
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

sg.theme(utg.settingsForm.getSettings(application=application_settings, item="Theme"))


class Layout :

    # ------ Menu Definition ------ #
    menu_browse = ['&Browse', ['All &Data ...::M_ALLDATA',
                               '&Events ...::M_EVENTS', '&Contexts ...::M_CONTEXTS', 'Enri&chers ...::M_ENRICHERS',
                               '&Rules ...::M_RULES',   '&Actions ...::M_ACTIONS',   '&Templates ...::M_TEMPLATES']]

    menu_def = [['&File',     ['&Exit::M_EXIT', '---',
                               'BackUp &FS Store::M_BACKUP_FS_STORE',              'BackUp &DS Store::M_BACKUP_DS_STORE', '---',
                               '&Load DataSet into DS Store::M_LOAD_DS_STORE',     'Load DataSet into FS &Store::M_LOAD_FS_STORE']],
                menu_browse,
                ['&Settings', ['Theme, &Editor ...::M_SETTINGS', 'Toggle &Output::M_TOGGLE_OUTPUT', 'Toggle &Debug::M_DEBUG']],
                ['&Help',     [ '&Error ...::M_ERROR', '&How To ...::M_HELP', '---', '&About ...::M_ABOUT']]]

    systemLayout = [
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
    def createOpenapiSchemaButonsLayout(Resource: str):
        BtLayout = Layout.addButonsLayout(None,     Resource, 'Schema', color=('springgreen4', 'white'))
        BtLayout = Layout.addButonsLayout(BtLayout, Resource, 'OpenAPI', color=('springgreen4', 'white'))
        return BtLayout

    @staticmethod
    def addButonsLayout(Layout, Resource: str, Label : str, color=('white', 'springgreen4')):
        if (Layout is None) : Layout = [[]]
        return [Layout[0] + [sg.Button(" "+Label+" ",   button_color=color, key=Resource+"/"+Label.strip()+"Bt")]]

    @staticmethod
    def createRestLayout(Resource : str, InitialContext: str= "Context Input", withContext=False):
        if (withContext):
            return [sg.TabGroup([
                 [sg.Tab(' Output ',  [[sg.Multiline(default_text='', font=("Courier", 8), size=(43, 32), key=Resource + "/Output")]]),
                  sg.Tab('  Rest  ',  [[sg.Multiline(default_text='', font=("Courier", 8), size=(43, 32), key=Resource + "/Rest")]])]])]
        else:
            return [sg.TabGroup([
                 [sg.Tab(' Input ',   [[sg.Multiline(default_text='', font=("Courier", 8), size=(43, 32), key=Resource + "/Context")]]),
                  sg.Tab(' Output ',  [[sg.Multiline(default_text='', font=("Courier", 8), size=(43, 32), key=Resource + "/Output")]]),
                  sg.Tab('  Rest  ',  [[sg.Multiline(default_text='', font=("Courier", 8), size=(43, 32), key=Resource + "/Rest")]])]])]

    @staticmethod
    def createHeaderLayout(Resource : str, Version : bool = False):
        if (Version):
            return [[sg.Text(Resource + " Management", size=(34, 1), justification='left', font=("Courier", 15, 'bold'), key=Resource + "/Header"),
                     sg.Text(Resource + " Operations", size=(50, 1), justification='left', font=("Courier",  9, 'bold'), key=Resource + "/Title"),
                     ],
                    [sg.Text('Name        : ', size=(15, 1)), sg.InputText(Resource + " Name", size=(40, 1), key=Resource + "/Name"),
                     sg.Text('TimeStamp   : ', size=(15, 1)), sg.InputText('TimeStamp',      size=(30, 1),   key=Resource+"/TimeStamp", text_color='grey'),
                     ],
                    [
                     sg.Text('Tag         : ', size=(15, 1)), sg.InputText('Backup Tag',     size=(40, 1),   key=Resource+"/Tag"),
                     sg.Text('Version     : ', size=(15, 1)), sg.InputText('Version',        size=(30, 1),   key=Resource+"/Version", text_color='grey')
                    ],
                    [sg.Text('Description : ', size=(15, 1)), sg.InputText('Description', size=(91, 1),      key=Resource+"/Description"),
                     ],
                    [sg.Text('Identifier : ' , size=(15, 1)), sg.InputText('Identifier', size=(91, 1),       key=Resource + "/Identifier", readonly=True),
                     ]]
        else :
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
                     sg.Button(' Edit ',    button_color=('white', 'blue'), key=Resource + "/EditBt"),
                     sg.Button(' Save ',    button_color=('white', 'blue'), key=Resource + "/SaveBt"),
                     sg.Button(' Delete ',  button_color=('white', 'firebrick3'), key=Resource + "/DeleteBt"),
                     ]
        if (not buttonsList) :
            return [default_button_list]
        else:
            return [default_button_list + buttonsList[0] ]

    @staticmethod
    def createBodyLayout(Resource : str, InitialText: str = "Text Input", withContext=False):
        return [[sg.Listbox(values=('(Click List)', ''), font=("Courier", 12), size=(20, 25), enable_events=True,  key=Resource+"/Listing"),
                 sg.Multiline(default_text="( < Select "+Resource+")", size=(55, 26), font=("Courier", 12), key=Resource+"/Text")]
                 # + createRestLayout(Resource, InitialText, withContext=False)
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
            DS_CATALOG_TABLIST = Layout.addTabTabGroup(DS_CATALOG_TABLIST, "DS", str(resource).capitalize(), Layout.createOpenapiSchemaButonsLayout(resource))
        DS_CATALOG_GROUP = [[sg.TabGroup([DS_CATALOG_TABLIST], enable_events=True, font=("Courier", 12), key='DS Catalog/Tabs')]]

        DS_USERS_TABLIST = []
        for resource in aep.AEP_APPLICATION_USER_PROFILES_RESSOURCES:
            DS_USERS_TABLIST = Layout.addTabTabGroup(DS_USERS_TABLIST, "DS", str(resource).capitalize(), Layout.createOpenapiSchemaButonsLayout(resource))
        DS_USERS_GROUP = [[sg.TabGroup([DS_USERS_TABLIST], enable_events=True, font=("Courier", 12), key='DS Users/Tabs')]]

        FS_CATALOG_TABLIST = []
        for resource in aep.AEP_CATALOG_RESSOURCES:
            FS_CATALOG_TABLIST = Layout.addTabTabGroup(FS_CATALOG_TABLIST, "FS", str(resource).capitalize(), Layout.createOpenapiSchemaButonsLayout(resource))
        FS_CATALOG_GROUP = [[sg.TabGroup([FS_CATALOG_TABLIST], enable_events=True, font=("Courier", 12), key='FS Catalog/Tabs')]]

        FS_USERS_TABLIST = []
        for resource in aep.AEP_APPLICATION_USER_PROFILES_RESSOURCES:
            FS_USERS_TABLIST = Layout.addTabTabGroup(FS_USERS_TABLIST, "FS", str(resource).capitalize(), Layout.createOpenapiSchemaButonsLayout(resource))
        FS_USERS_GROUP = [[sg.TabGroup([FS_USERS_TABLIST], enable_events=True, font=("Courier", 12), key='FS Users/Tabs')]]

        WS_TABLIST = []
        for resource in aep.WSO2_RESSOURCES:
            WS_TABLIST = Layout.addTabTabGroup(WS_TABLIST, "WS", str(resource).capitalize())
        WS_GROUP = [[sg.TabGroup([WS_TABLIST], enable_events=True, font=("Courier", 12), key='WS WSO2/Tabs')]]

        TAB_GROUP = sg.TabGroup([[sg.Tab(' FS Catalog ', FS_CATALOG_GROUP,     font=("Courier", 12), background_color='red',     key='FS_CatalogTab'),
                                  sg.Tab(' FS Users ',   FS_USERS_GROUP,       font=("Courier", 12), background_color='red',     key='FS_UsersTab'),
                                  sg.Tab(' DS Catalog ', DS_CATALOG_GROUP,     font=("Courier", 12), background_color='green',   key='DS_CatalogTab'),
                                  sg.Tab(' DS Users ',   DS_USERS_GROUP,       font=("Courier", 12), background_color='green',   key='DS_UsersTab'),
                                  sg.Tab(' WS WSO2 ',    WS_GROUP,             font=("Courier", 12), background_color='blue',    key='WS_Tab'),
                                  sg.Tab(' System ',     Layout.systemLayout,  font=("Courier", 12),                             key='System_Tab')]],
                    enable_events=True, font=("Courier", 12), key='Tabs')

        mainLayout = [
                  [sg.Menu(Layout.menu_def, tearoff=True)],
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
        self.initWindow()

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

    def error(self, text="Error"):
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
        self.window.set_cursor("wait")
        return self.status(text, color="orange")

    def statusDone(self, text="Done."):
        self.window.set_cursor("arrow")
        if (self.isError()) : return True
        return self.status(text, color="green")

    def statusReady(self, text="Ready"):
        self.window.set_cursor("arrow")
        if (self.isError()) : return True
        return self.status(text, color="blue")

    def statusError(self, text="Error"):
        self.window.set_cursor("arrow")
        text = text + " : " + self.error_text
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
            self.error(str(e))
            return False

    ###
    def refreshFile(self):
        if (self.Resources == None) or (self.Resources == "") or (self.current_element == None) or (self.current_element == ""):
            return False
        res  = self.current_tab
        name = self.current_element
        if (self.Resources not in settings["Extensions"].keys()):
            logger.error("No Extension defined in settings for : "+self.Resources)
            return False
        filepath = tempfile.gettempdir() + os.sep + res + "_" + name + "." + settings["Extensions"][res]
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
            self.current_content_ext = settings["Extensions"][self.current_tab]
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

    ###
    ### Common
    ###

    def handleOutput(self, event : str, command : str, result : str, payload : str = ""):
        self.last_output = result
        output = self.last_output  # self.quotedTextToText(self.last_output)
        self.setWidgetValue("Output", output)
        if (self.output_popup):
            sg.PopupScrolled(output, title=event + " : " + command, size=(80, 30))
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
        self.setWidgetValue("Input",  "( < Select "+self.Resource+")")
        self.setWidgetValue("Rest",   "NO ACCESS")
        self.setWidgetValue("Output", "NO ACCESS")

    def updateAepEntry(self, entry : str , what : str = None, version=True):
        if (what == None):
            self.current_element = self.getWidgetValue(self.Resources + "/Name")
        else:
            self.current_element = what
        obj = ut.loadDataContent(entry)
        if ((not obj) or ("id" not in obj)):
            ident = "(No identifier found)"
            self.setWidgetValue(self.Resources + "/Name",        str(what))
            self.setWidgetValue(self.Resources + "/Identifier",  str(ident))
            self.setWidgetValue(self.Resources + "/Text",        str(entry))
            self.setWidgetValue(self.Resources + "/Output",      str(entry))
            self.setWidgetValue(self.Resources + "/Description", str(aep.StoreManager.get_description(str(self.Resources), str(ident))))
        else:
            ident = obj["id"]
            self.setWidgetValue(self.Resources + "/Name",        str(what))
            self.setWidgetValue(self.Resources + "/Identifier",  str(ident))
            self.setWidgetValue(self.Resources + "/Text",        str(entry))
            self.setWidgetValue(self.Resources + "/Output",      str(entry))
            self.setWidgetValue(self.Resources + "/Description", str(aep.StoreManager.get_description(str(self.Resources), str(ident))))
        """
        self.restRequest(self.resources+"/" + self.current_element + "?VC=False")
        self.setWidgetValue("Tag",          "(Tag)")
        self.setWidgetValue("Description",  "(Description)")
        self.setWidgetValue("Version",      "(Version)")
        self.setWidgetValue("TimeStamp",    "(TimeStamp)")
        if (version == True):
            self.restRequest(self.resources+"/" + self.current_element + "?versioncontrol")
            if (self.reqServer.d_data):
                self.setWidgetValue("Tag", self.reqServer.d_data["VersionControl/Tag"])
                self.setWidgetValue("Description", self.reqServer.d_data["VersionControl/Comment"])
                self.setWidgetValue("Version", self.reqServer.d_data["VersionControl/Version"])
                self.setWidgetValue("TimeStamp", self.reqServer.d_data["VersionControl/TimeStamp"])
        """

    def updateWso2Entry(self, entry : str , what : str = None, version=True):
        if (what == None):
            self.current_element = self.getWidgetValue(self.Resources + "/Name")
        else:
            self.current_element = what
        obj = ut.loadDataContent(entry)
        if ("role" in obj):  # WS Users
            self.setWidgetValue(self.Resources + "/Name",        str(obj["name"]))
            self.setWidgetValue(self.Resources + "/Identifier",  str(obj["name"]))
            self.setWidgetValue(self.Resources + "/Text",        str(entry))
            self.setWidgetValue(self.Resources + "/Output",      str(entry))
            self.setWidgetValue(self.Resources + "/Description", str(obj["role"]))
            return

        if ((not obj) or ("id" not in obj)):
            ident = "(No identifier found)"
            self.setWidgetValue(self.Resources + "/Name",        str(what))
            self.setWidgetValue(self.Resources + "/Identifier",  str(ident))
            self.setWidgetValue(self.Resources + "/Text",        str(entry))
            self.setWidgetValue(self.Resources + "/Output",      str(entry))
            self.setWidgetValue(self.Resources + "/Description", str(aep.StoreManager.get_description(str(self.Resources), str(ident))))
        else:
            ident = obj["id"]
            self.setWidgetValue(self.Resources + "/Name",        str(what))
            self.setWidgetValue(self.Resources + "/Identifier",  str(ident))
            self.setWidgetValue(self.Resources + "/Text",        str(entry))
            self.setWidgetValue(self.Resources + "/Output",      str(entry))
            self.setWidgetValue(self.Resources + "/Description", str(aep.StoreManager.get_description(str(self.Resources), str(ident))))
        """
        self.restRequest(self.resources+"/" + self.current_element + "?VC=False")
        self.setWidgetValue("Tag",          "(Tag)")
        self.setWidgetValue("Description",  "(Description)")
        self.setWidgetValue("Version",      "(Version)")
        self.setWidgetValue("TimeStamp",    "(TimeStamp)")
        if (version == True):
            self.restRequest(self.resources+"/" + self.current_element + "?versioncontrol")
            if (self.reqServer.d_data):
                self.setWidgetValue("Tag", self.reqServer.d_data["VersionControl/Tag"])
                self.setWidgetValue("Description", self.reqServer.d_data["VersionControl/Comment"])
                self.setWidgetValue("Version", self.reqServer.d_data["VersionControl/Version"])
                self.setWidgetValue("TimeStamp", self.reqServer.d_data["VersionControl/TimeStamp"])
        """

    def clearAepEntry(self, output=True):
        self.setWidgetValue("Name",         "")
        self.setWidgetValue("Text",         "( < Select "+self.Resource+")")
        self.setWidgetValue("Input",        "( < Select "+self.Resource+")")
        self.setWidgetValue("Tag",          "")
        self.setWidgetValue("Description",  "")
        self.setWidgetValue("Identifier",  "")
        self.setWidgetValue("Version",      "")
        self.setWidgetValue("TimeStamp",    "")
        if (output):
            self.setWidgetValue("Output",       "")
            self.setWidgetValue("Rest",         "")

    ###
    ### System
    ###

    ###
    def handleSystemRequest(self, request) -> bool:
        try:
            self.restRequest(request)
            self.setWidgetValue("System/Output", self.reqServer.r_text)
            return self.reqServer.isError()
        except Exception as e:
            self.setWidgetValue("System/Output", str(e))
            self.error(str(e))
            return False

    ###
    def handleSystemEvent(self, event, values):

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
    ### AEP FS Catalog
    ###

    def eventResource(self, event) -> str:
        resource = event
        if ("/" in event):
            resource = re.sub("/.*$", "", resource)
        return resource

    def eventWidget(self, event) -> str:
       if ("/" in event):
           return re.sub("^.*/", "", self.current_event)
       else:
           return event

    def checkPayload(self, payload : str) -> bool :
        self.error_text = None
        try :
            json.loads(payload)
        except Exception as err:
            self.error(str(err))
            return False
        res = aep.StoreManager().check_schema(payload, self.aep_store)
        if (res) :
            self.error(str(res))
            return False
        return True

    def aepctl(self, command, event="Unkown"):
        command = aep_debug + command
        logger.info("aepctl command : " + command)
        self.error(None)
        self.window.set_cursor("wait")
        res = aep.main(command, interactive=False)
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
        self.setWidgetValue("Output", res)
        return True

    def loadEntry(self, event, entry_id : str = None):
        resource = self.eventResource(event)
        if (not entry_id) :
            if (len(self.current_values[resource +"/Listing"]) == 0):
                return False
            entry_id = self.current_values[resource +"/Listing"][0]
        cmd = resource + " get " + entry_id
        res = self.aepctl(cmd, event)
        if self.isError():
            return False
        if (event.startswith("WS")) :
            self.updateWso2Entry(res, entry_id)
        else:
            self.updateAepEntry(res, entry_id)
        self.setWidgetValue("Output", res)
        return True

    def deleteResource(self, event, entry_id : str = None):
        resource = self.eventResource(event)
        if (not entry_id) :
            entry_id = self.current_values[resource +"/Listing"][0]
        cmd = resource + " delete " + entry_id
        res = self.aepctl(cmd, event)
        if self.isError():
            return False
        self.updateAepEntry(res, entry_id)
        self.setWidgetValue("Output", res)
        self.clearAepEntry(output=False)
        self.loadList(event)
        return True

    def saveResource(self, event, entry_id : str = None):
        resource = self.eventResource(event)
        if (not entry_id) :
            entry_id = self.current_values[resource +"/Listing"][0]
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
        self.setWidgetValue("Output", res)
        self.clearAepEntry(output=False)
        self.loadList(event)
        return True

    def backupResource(self, resource):
        self.Resource = resource
        event = self.Resource + "/BackUp"
        self.statusDoing("BackUp " + self.Resource + " ...")
        bupdir = utg.directorySelectorForm(buttonName="BackUp", windowTitle="Select BackUp Directory")
        if (not bupdir): return False
        cmd = self.Resource + " backUp " + bupdir
        res = self.aepctl(cmd, self.Resource + "/backUp")
        self.statusDone("BackedUp " + self.Resource + ".")
        return True

    def loadDataSet(self, resource):
        self.Resource = resource
        event = self.Resource + "/LoadDataSet"
        self.statusDoing("Load DataSet " + self.Resource + " ...")
        loadPath = utg.fileDirectorySelectorForm(buttonName="Load", windowTitle="Select Load Data Set")
        if (not loadPath): return False
        cmd = self.Resource + " load " + loadPath
        res = self.aepctl(cmd, self.Resource + "/LoadDataSet")
        self.setWidgetValue(self.Resources + "/Text", str(res))
        self.statusDone("Loaded DataSet " + self.Resource + ".")
        return True

    def handleAepEvent(self, event, values):

        widget   = self.eventWidget(event)

        if ("Tabs" in widget):  # Tab Focus
            self.loadList(self.current_value)
            return True

        if (widget == "ListBt"):  # Load List
            self.loadList(event)
            return self.statusDone("Listed "+self.Resource+".")

        if (widget == "Listing"):  # Load List
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
            self.checkPayload(self.getWidgetValue(self.Resources + "/Text"))
            if (self.isError()): return True
            self.statusDoing("Saving "+self.Resource+" ...")
            entry    = self.getWidgetValue(self.Resources + "/Text")
            dentry   = json.loads(entry)
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
            self.statusDoing("Load "+self.Resource+" ...")
            self.loadEntry(event, self.getWidgetValue("Name"))
            return self.statusDone("Load "+self.Resource+".")

        if (widget == "SchemaBt"):
            self.statusDoing("Schema "+self.Resource+" ...")
            cmd = self.eventResource(event) + " schema "
            res = self.aepctl(cmd, event)
            self.setWidgetValue(self.Resources + "/Text",        str(res))
            return self.statusDone("Schema "+self.Resource+".")

        if (widget == "OpenAPIBt"):
            self.statusDoing("OpenAPI "+self.Resource+" ...")
            cmd = self.eventResource(event) + " openapi "
            res = self.aepctl(cmd, event)
            self.setWidgetValue(self.Resources + "/Text",        str(res))
            return self.statusDone("OpenAPI "+self.Resource+".")

        if (event == self.Resources + "/BackUpBt"):
            self.statusDoing("BackUp "+self.Resource+" ...")
            if (sg.PopupYesNo("BackUp " + self.Resource + " ?", title="BackUp ?") != "Yes"): return True
            cmd = self.eventResource(event) + " backUp "
            res = self.aepctl(cmd, event)
            self.setWidgetValue(self.Resources + "/Text",        str(res))
            return self.statusDone("BackedUp "+self.Resource+".")

        if (event == self.Resources + "/EditBt"):
            self.statusDoing("Editing "+self.Resource+" ...")
            self.loadEntry()
            content = self.getWidgetValue("Text", "NO_TEXT")
            self.openFile(content, self.Resources, self.current_element)
            return self.statusDone("Edit "+self.Resource+".")

    def handleWso2Event(self, event, values):

        widget   = self.eventWidget(event)

        if ("Tabs" in widget):  # Tab Focus
            self.loadList(self.current_value)
            return True

        if (widget == "ListBt"):  # Load List
            self.loadList(event)
            return self.statusDone("Listed "+self.Resource+".")

        if (widget == "Listing"):  # Load List
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
            self.checkPayload(self.getWidgetValue(self.Resources + "/Text"))
            if (self.isError()): return True
            self.statusDoing("Saving "+self.Resource+" ...")
            entry    = self.getWidgetValue(self.Resources + "/Text")
            dentry   = json.loads(entry)
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
            self.statusDoing("Load "+self.Resource+" ...")
            self.loadEntry(event, self.getWidgetValue("Name"))
            return self.statusDone("Load "+self.Resource+".")

        if (widget == "SchemaBt"):
            self.statusDoing("Schema "+self.Resource+" ...")
            cmd = self.eventResource(event) + " schema "
            res = self.aepctl(cmd, event)
            self.setWidgetValue(self.Resources + "/Text",        str(res))
            return self.statusDone("Schema "+self.Resource+".")

        if (widget == "OpenAPIBt"):
            self.statusDoing("OpenAPI "+self.Resource+" ...")
            cmd = self.eventResource(event) + " openapi "
            res = self.aepctl(cmd, event)
            self.setWidgetValue(self.Resources + "/Text",        str(res))
            return self.statusDone("OpenAPI "+self.Resource+".")

        if (event == self.Resources + "/BackUpBt"):
            self.statusDoing("BackUp "+self.Resource+" ...")
            if (sg.PopupYesNo("BackUp " + self.Resource + " ?", title="BackUp ?") != "Yes"): return True
            cmd = self.eventResource(event) + " backUp "
            res = self.aepctl(cmd, event)
            self.setWidgetValue(self.Resources + "/Text",        str(res))
            return self.statusDone("BackedUp "+self.Resource+".")

        if (event == self.Resources + "/EditBt"):
            self.statusDoing("Editing "+self.Resource+" ...")
            self.loadEntry(event)
            content = self.getWidgetValue("Text", "NO_TEXT")
            self.openFile(content, self.Resources, self.current_element)
            return self.statusDone("Edit "+self.Resource+".")

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
            if (self.current_tab in settings["Extensions"].keys()):
                self.current_content_ext = settings["Extensions"][self.current_tab]
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

    def refresh(self):
        if (self.no_refresh) : return
        if (self.current_tab == "Tabs"):
            self.current_tab = self.current_action
            self.current_element = ""
            self.current_action  = "Focus"
        title = application
        if (self.current_event == None) : return
        if (self.current_tab != None)     and (self.current_tab != "")     : title = "[" + self.current_event + "]"
        # if (self.current_tab != None)     and (self.current_tab != "")     : title = self.current_tab
        if (self.current_tab == "FileStores")                              : title =  title + " - " + self.current_fs
        if (self.current_element != None) and (self.current_element != "") : title =  title + " : [" + self.current_element + "]"
        if (self.current_action != None)  and (self.current_action != "")  : title =  title + " - " + self.current_action
        self.udata[self.current_tab+"/Title"] = title
        # self.window.Element("Title").Update(title)

        # Refresh Widgets with Updated Values
        # self.refreshFile()
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

    def run(self):

        self.window = sg.Window(application, Layout.createMainLayout(), default_element_size=(80, 1), grab_anywhere=False, resizable=False)

        # Initial Inits
        initDone = False

        # The Event Loop
        while True:
            self.refresh()
            if (self.current_event != "System/Timeout"):
                logger.info("Event   : " + str(self.current_event) + " - " + str("Done"))
            if (initDone): self.window.set_cursor("arrow")
            self.current_event, self.current_values = self.window.Read(timeout=refresh_timeout, timeout_key="System/Timeout")  # in ms
            if (initDone): self.window.set_cursor("wait")
            if self.current_event is None: break
            self.no_refresh = False
            self.logEvent()

            # System Event Processing
            if (self.current_event == "System/Timeout"):
                # logger.info("System/Timeout")
                self.no_refresh = True
                if (initDone == False):
                    # Initial Inits
                    initDone = True
                # self.refreshFile()
                continue

            if (self.current_event == 'About ...') or ('M_ABOUT' in self.current_event):
                self.current_event  = "System/About"
                text = "      Amdocs Exposure Platform\n  Contact: bheuse@amdocs.com"
                text = text + "\n\nConfiguration File:\n" + utg.settingsForm.getSettingsFile()
                self.statusDone("About.")
                sg.PopupScrolled(text, title="About ...", size=(35, 3))
                continue

            if (self.current_event == "Error ...") or ('M_ERROR' in self.current_event):  # Show Last Error
                self.current_event  = "System/Error"
                self.status("Last Error", "red")
                self.logEvent("Error")
                sg.PopupScrolled(self.error_text, title="Last Error :", size=(60, 20))
                continue

            if (self.current_event == 'BackUp FS Store') or ('M_BACKUP_FS_STORE' in self.current_event):
                self.backupResource("FS providers")
                continue

            if (self.current_event == 'BackUp DS Store') or ('M_BACKUP_DS_STORE' in self.current_event):
                self.backupResource("DS providers")
                continue

            if (self.current_event == 'Load DataSet into DS Store') or ('M_LOAD_DS_STORE' in self.current_event):
                self.loadDataSet("DS providers")
                continue

            if (self.current_event == 'Load DataSet into FS Store') or ('M_LOAD_FS_STORE' in self.current_event):
                self.loadDataSet("FS providers")
                continue


            ###
            ### Menu Events
            ###

            # Edit Settings
            if (self.current_event == 'Theme, Editor ...') or ('M_SETTINGS' in self.current_event):
                self.status("Edit Settings")
                utg.settingsForm.editSettings(application=application_settings, no_server = True)
                sg.theme(utg.settingsForm.getSettings(application=application_settings, item="Theme"))
                continue

            # Verbose ON/OFF
            if (self.current_event == 'Toggle Output') or ('M_TOGGLE_OUTPUT' in self.current_event):
                self.output_popup = not self.output_popup
                self.statusDone("Toggled Output")
                continue

            # Verbose ON/OFF
            if (self.current_event == 'Toggle Debug') or ('M_DEBUG' in self.current_event):
                global aep_debug
                if (aep_debug == ""):
                    aep_debug = "-v "
                    ut.Verbose.swap_verbose()
                    self.statusDone("Verbose ON")
                else:
                    aep_debug = ""
                    ut.Verbose.swap_verbose()
                    self.statusDone("Verbose OFF")
                continue

            # About
            if (self.current_event == 'About ...') or ('M_ABOUT' in self.current_event):
                utg.aboutPopup(configuration_file=utg.settingsForm.getSettingsFile())
                continue

            # How to / Help
            if (self.current_event == 'How To ...') or ('M_HELP' in self.current_event):
                sg.PopupScrolled("Coming Soon ...", title="Help on the Rule Editor", size=(40, 20))
                continue

            # Exit
            if ((self.current_event == "Exit") or ('M_EXIT' in self.current_event)):
                self.status("Exit ...")
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

            #  Event Processing
            self.logEvent("Event")
            self.collectEvent(self.current_event, self.current_values)
            self.status("OK", color="green")
            self.logEvent("Details")

            if (self.current_event.startswith("WS")) :
                if self.handleWso2Event(self.current_event, self.current_values):      continue
            if self.handleAepEvent(self.current_event, self.current_values):           continue
            if self.handleSystemEvent(self.current_event, self.current_values):        continue
            self.error("Widget Event Not Implemented : "+self.current_event+" - "+str(self.current_value))


MainGUI().run()


'''
# ------ Column Definition ------ #
column1 = [[sg.Text('Column 1', background_color='#F7F3EC', justification='center', size=(10, 1))],
           [sg.Spin(values=('Spin Box 1', '2', '3'), initial_value='Spin Box 1')],
           [sg.Spin(values=('Spin Box 1', '2', '3'), initial_value='Spin Box 2')],
           [sg.Spin(values=('Spin Box 1', '2', '3'), initial_value='Spin Box 3')]]

layout = [
    [sg.Menu(menu_def, tearoff=True)],
    [sg.Text('All graphic widgets in one window!', size=(30, 1), justification='center', font=("Helvetica", 25),
             relief=sg.RELIEF_RIDGE)],
    [sg.Text('Here is some text.... and a place to enter text')],
    [sg.InputText('This is my text')],
    [sg.Frame(layout=[
        [sg.Checkbox('Checkbox', size=(10, 1)), sg.Checkbox('My second checkbox!', default=True)],
        [sg.Radio('My first Radio!     ', "RADIO1", default=True, size=(10, 1)),
         sg.Radio('My second Radio!', "RADIO1")]], title='Options', title_color='red', relief=sg.RELIEF_SUNKEN,
        tooltip='Use these to set flags')],
    [sg.Multiline(default_text='This is the default Text should you decide not to type anything', size=(35, 3)),
     sg.Multiline(default_text='A second multi-line', size=(35, 3))],
    [sg.InputCombo(('Combobox 1', 'Combobox 2'), size=(20, 1)),
     sg.Slider(range=(1, 100), orientation='h', size=(34, 20), default_value=85)],
    [sg.InputOptionMenu(('Menu Option 1', 'Menu Option 2', 'Menu Option 3'))],
    [sg.Listbox(values=('Listbox 1', 'Listbox 2', 'Listbox 3'), size=(30, 3)),
     sg.Frame('Labelled Group', [[
         sg.Slider(range=(1, 100), orientation='v', size=(5, 20), default_value=25),
         sg.Slider(range=(1, 100), orientation='v', size=(5, 20), default_value=75),
         sg.Slider(range=(1, 100), orientation='v', size=(5, 20), default_value=10),
         sg.Column(column1, background_color='#F7F3EC')]])],
    [sg.Text('_' * 80)],
    [sg.Text('Choose A Folder', size=(35, 1))],
    [sg.Text('Your Folder', size=(15, 1), auto_size_text=False, justification='right'),
     sg.InputText('Default Folder'), sg.FolderBrowse()],
    [sg.Submit(tooltip='Click to submit this window'), sg.Cancel()]
'''