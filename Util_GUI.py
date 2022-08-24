import PySimpleGUI as sg
import json
import platform
import tempfile
import os
import re
from pathlib import Path
import Util as ut
import subprocess


import logging
logging.basicConfig(format='%(levelname)s:%(name)s:%(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

servers_list = ['(Enter or Select Server)',
                '(localhost) 127.0.0.1:30106',
                '(format) server:port']

theme_list = sg.theme_list()

default_settings = {
    "Application"  : "Settings" ,
    "Server"       : "127.0.0.1:5000" ,
    "Theme"        : "Tan",
    "Editor"       : "idle.bat",
    "ServerList"   : servers_list,
    "ThemeList"    : theme_list
}


class settingsForm():

    def_editor = str(Path.home()) + "/AppData/Local/Programs/Python/Python39/Lib/idlelib/idle.bat"
    SETTINGS_KEYS_TO_ELEMENT_KEYS = {'Server': '-SERVER-', 'Theme': '-THEME-' , 'Editor': '-EDITOR-'}

    def __init__(self, application, default_settings = default_settings):
        self.application    = application
        self.title          = application +" Settings."
        self.settings       = default_settings
        self.settings_file  = tempfile.gettempdir() + os.sep + application.replace(" ", "_")+"_settings_gui.json"
        self.current_event  = ""
        self.current_values = ""

        # Load or Save Default Configuration
        settings = ut.loadFileData(self.settings_file)
        if (settings == None):
            self.settings = default_settings
            ut.saveJsonFile(self.settings, self.settings_file)
        else :
            self.settings = settings
        logger.info("Configuration Settings : "+json.dumps(settings,indent=2))

        if ("Theme"  in self.settings) :
            sg.theme(self.settings['Theme'])

    def create_window(self, no_server : bool = True):
        if ("Theme"  in self.settings) :
            sg.theme(self.settings['Theme'])

        col_1 = 10 ; col_2 = 25 ; col_3 = 8
        def TextLabel(text):
            return sg.Text(text + ':', justification='r', size=(col_1, 1), key=text)

        if (no_server) :
            settingsForm.SETTINGS_KEYS_TO_ELEMENT_KEYS = { 'Theme': '-THEME-', 'Editor': '-EDITOR-'}
            layout = [[TextLabel('Theme'),       sg.Combo(theme_list, size=(col_2, 1), key='-THEME-', enable_events=True), sg.Button("Test", key='-TEST_THEME-', size=(col_3, 1))],
                      [TextLabel('Editor'),      sg.InputText(settingsForm.def_editor, size=(col_2 + 2, 1), key='-EDITOR-', enable_events=True), sg.FileBrowse(target='-EDITOR-', size=(col_3, 1))],
                      [sg.Button('Save', size=(col_3, 1)), sg.Button('Reload', size=(col_3, 1)), sg.Text("", size=(col_1 + col_2 - col_3 * 2 - 4, 1)), sg.Button('Close', size=(col_3, 1))]]
        else:
            settingsForm.SETTINGS_KEYS_TO_ELEMENT_KEYS = {'Server': '-SERVER-', 'Theme': '-THEME-', 'Editor': '-EDITOR-'}
            layout = [[TextLabel('Server'),      sg.Combo(self.settings["ServerList"], size=(col_2, 1), key='-SERVER-', enable_events=True,),    sg.Button("Test",key='-TEST_SERVER-', size=(col_3, 1))],
                      [TextLabel('Theme'),       sg.Combo(theme_list,                  size=(col_2, 1), key='-THEME-',  enable_events=True),     sg.Button("Test",key='-TEST_THEME-',  size=(col_3, 1))],
                      [TextLabel('Editor'),      sg.InputText(settingsForm.def_editor, size=(col_2+2, 1), key='-EDITOR-', enable_events=True),   sg.FileBrowse(target='-EDITOR-',      size=(col_3, 1))],
                      [sg.Button('Save',size=(col_3, 1)), sg.Button('Reload',size=(col_3, 1)), sg.Text("",size=(col_1+col_2-col_3*2-4,1)),sg.Button('Close',size=(col_3, 1))]]
        self.window = sg.Window(self.title, layout, finalize=True,keep_on_top=True)
        self.update_window()
        return self.window

    def update_window(self):
        for key in settingsForm.SETTINGS_KEYS_TO_ELEMENT_KEYS:  # Update window with the values read from settings file
            try:
                self.window[settingsForm.SETTINGS_KEYS_TO_ELEMENT_KEYS[key]].update(value=self.settings[key])
            except:
                logger.exception("Problem updating window from settings. Key : "+ key)
        if ("Theme"  in self.settings) :
            sg.theme(self.settings['Theme'])

    def save_settings(self):
        for key in settingsForm.SETTINGS_KEYS_TO_ELEMENT_KEYS:  # update window with the values read from settings file
            try:
                self.settings[key] = self.current_values[settingsForm.SETTINGS_KEYS_TO_ELEMENT_KEYS[key]]
            except Exception as e:
                logger.exception("Problem updating window from settings. Key : "+ key)
        ut.saveJsonFile(self.settings, self.settings_file)

    def load_settings(self):
        self.settings = ut.loadFileData(self.settings_file)
        self.update_window()
        if ( 'Server' in settingsForm.SETTINGS_KEYS_TO_ELEMENT_KEYS):
            self.window['Server'].Update("Server:", text_color="black")

    def checkServer(self, new_Server):
        server = re.sub("^.*\(.*\)","",new_Server).strip()
        try:
            rq = ut.Request(server)
            rq.get("help")
            if rq.isError():
                logger.error("Server Down : " + server)
                self.window['Server'].Update("Server Down:", text_color="red")
                return False
        except Exception as e:
            logger.exception("LookUp Sever")
            logger.error("Server Down : "+ server)
            self.window['Server'].Update("Server Down:", text_color="red")
            return False
        logger.info("Server UP : " + server)
        self.window['Server'].Update("Server Up:", text_color = "green")
        return True

    def setServer(self, new_Server):
        self.server = re.sub("^.*\(.*\)","",new_Server).strip()
        self.settings["Server"] = new_Server
        if (new_Server) and (new_Server not in self.settings["ServerList"]):
            self.settings["ServerList"].insert(1,new_Server)
        return self.server

    def manageSettings(self, no_server : bool = True):
        self.window = self.create_window(no_server = no_server)
        while True:  # Event Loop
            self.current_event, self.current_values = self.window.Read(timeout=200, timeout_key="Timeout")  # in ms
            if self.current_event in (None, 'Exit'): break
            if self.current_event == "Timeout": continue
            logger.info("Event   : " + str(self.current_event))
            if self.current_event == '-TEST_THEME-' or self.current_event == '-THEME-':
                # sg.theme_previewer()
                sg.theme(self.current_values['-THEME-'])
                sg.popup_get_text('This is {}'.format(self.current_values['-THEME-']),default_text="Restart to apply.",keep_on_top=True,title="Theme Sample",size=(50,1))
                self.settings["Theme"] = self.current_values['-THEME-']
            if self.current_event == '-TEST_SERVER-' or self.current_event == '-SERVER-':
                if (self.checkServer(self.current_values['-SERVER-'])):
                    self.setServer(self.current_values['-SERVER-'])
            if self.current_event == 'Save':
                self.save_settings()
                break
            if self.current_event == 'Reload':
                self.load_settings()
            if self.current_event == 'Close':
                break
        self.window.close()
        logger.info("Configuration : " + json.dumps(self.settings, indent=2))
        return self.settings

    @staticmethod
    def getSettings(application="test", item=None):
        form = settingsForm(application=application)
        if (item == None): return form.settings
        elif (item == "Server"):  return re.sub("^.*\(.*\)", "", form.settings[item]).strip()
        else: return form.settings[item]

    @staticmethod
    def getSettingsFile(application="test"):
        return settingsForm(application=application).settings_file

    @staticmethod
    def editSettings(application="test", no_server : bool = True):
        form = settingsForm(application=application)
        return form.manageSettings(no_server=no_server)

full_list   = [ "1" , '2' , '3' ,  "4" , "5"]
select_list = [ "4" , "5"]


def selectListForm(full_list, initial_list=[], title="List Selection", width=30, one=False, preview : ut.Repository = None) -> list:

    if (full_list == None):
        full_list = list()
    if (initial_list == None):
        initial_list = list()
    full_list.sort()
    initial_list.sort()
    if (initial_list!=None) :
        select_list  = initial_list.copy()
    else:
        select_list = list()
    width = width

    if (one): type = "One"
    else:     type = "Multiple"

    if (preview):
        selectLayout = [[sg.Text('Selection ' + type, size=(width + 1, 1)), sg.Text('Full List', size=(width, 1)),  sg.Text('Preview', size=(width, 1))]]
        selectLayout += [[sg.Listbox(key='-SELECT_LIST-', values=select_list, enable_events=True, size=(width + 3, 12)),
                          sg.Listbox(key='-FULL_LIST-', values=full_list, enable_events=True, size=(width + 3, 12)),
                          sg.Multiline(default_text="", size=(width + 3, 12), font=("Courier", 10), key='-PREVIEW-',                                       enable_events=False)
                          ]]
        selectLayout += [[sg.Button('All >>', size=(8, 1), key="-REMOVE_ALL-", disabled=one),
                          sg.Button('Remove =>', size=(width - 13, 1), key="-REMOVE-"),
                          sg.Text(""), sg.Checkbox(text="", key="-CHECK-", enable_events=True),
                          sg.Button('<= Add', size=(width - 13, 1), key="-ADD-"),
                          sg.Button('<< All', size=(8, 1), key="-ADD_ALL-", disabled=one),
                          sg.Text("No Selection", size=(width + 3, 1), key="-PREVIEW_TEXT-"),
                          ]]  # the buttons
    else:
        selectLayout = [[sg.Text('Selection ' + type, size=(width + 1, 1)), sg.Text('Full List', size=(width, 1))]]
        selectLayout += [[sg.Listbox(key='-SELECT_LIST-', values = select_list, enable_events=True, size=(width+3, 12)),
                         sg.Listbox(key='-FULL_LIST-',   values=full_list, enable_events=True, size=(width + 3, 12))
                        ]]
        selectLayout += [[sg.Button('All >>', size=(8, 1), key = "-REMOVE_ALL-", disabled=one), sg.Button('Remove =>', size=(width-13, 1), key = "-REMOVE-"),
                          sg.Text(""), sg.Checkbox(text="", key="-CHECK-", enable_events=True),
                          sg.Button('<= Add', size=(width - 13, 1), key="-ADD-"), sg.Button('<< All', size=(8, 1), key="-ADD_ALL-", disabled=one)
                          ]]  # the buttons
    selectLayout += [[sg.Button('Select', key = "-DONE-", size=(8, 1)), sg.StatusBar('[]', key = "-LIST-", size=(width+13, 1)), sg.Button('Cancel', key = "-CANCEL-", size=(8, 1))]]

    window = sg.Window(title, selectLayout)

    checkBox = True
    while True:
        event, values = window.read()
        if event in (None, 'Exit'):
            break
        elif event == '-ADD_ALL-':
            select_list = full_list.copy()
            window['-SELECT_LIST-'].Update(select_list)
            window['-LIST-'].Update(str(select_list))
            print(select_list)
        elif event == '-REMOVE_ALL-':
            select_list = list()
            window['-SELECT_LIST-'].Update(select_list)
            window['-LIST-'].Update(str(select_list))
            print(select_list)
        elif event == '-ADD-' or (checkBox and event == '-FULL_LIST-'):
            if values['-FULL_LIST-'] == None : continue
            if len(values['-FULL_LIST-']) == 0: continue
            if (one):
                select_list = list()
                select_list.append(values['-FULL_LIST-'][0])
            else:
                select_list.append(values['-FULL_LIST-'][0])
                select_list = list(set(select_list))
            select_list.sort()
            window['-SELECT_LIST-'].Update(select_list)
            window['-LIST-'].Update(str(select_list))
            if (preview):
                window['-PREVIEW-'].Update(str(preview.preview(values['-FULL_LIST-'][0])))
                window['-PREVIEW_TEXT-'].Update(str(preview.varDescription(values['-FULL_LIST-'][0])))
            print(select_list)
        elif event == '-REMOVE-' or (checkBox and event == '-SELECT_LIST-'):
            if values['-SELECT_LIST-'] == None : continue
            if len(values['-SELECT_LIST-']) == 0 : continue
            select_list.remove(values['-SELECT_LIST-'][0])
            window['-SELECT_LIST-'].Update(select_list)
            window['-LIST-'].Update(str(select_list))
        elif event == '-CHECK-':
            checkBox = not checkBox
            print("Check : " + str(checkBox))
        elif event == '-DONE-':
            window.close()
            print("Selection : "+ str(select_list))
            return select_list
        elif event == '-CANCEL-':
            break
    window.close()
    print("No Selection")
    return initial_list

formats = ["Json", "Yaml", "Flat", "Context", "Description", "Variables", "List", "Format", "Repository", "Conditions", "Python", "Content"]

TestTree = {
        "Name": "TestEventName",
        "TT": ["TestEventName", "tt"],
        "Parameters": {
            "Param1": "Val1",
            "Param2": "Val2",
            "Parameters3": {
                "Param1": "Val1",
                "Param2": "Val2"
            },
        },
        "Parameters2": {
            "Param1": "Val1",
            "Param2": "Val2"
        }
    }


def directorySelectorForm(buttonName : str = "Submit", windowTitle : str = 'Select Directory', chooseText : str = "Choose a folder: "):

    layout = [[sg.Text(chooseText), sg.Input(key="-IN2-", change_submits=True), sg.FolderBrowse(key="-IN-")],
              [sg.T(""), sg.Button(" "+buttonName+" "), sg.Button(" Cancel ")]]

    window = sg.Window(windowTitle, layout, size=(520, 70))

    while True:
        event, values = window.read()
        if event == sg.WIN_CLOSED or event == "Exit":
            window.close()
            return None
        elif buttonName in event:
            window.close()
            return values["-IN-"]
        elif "Cancel" in event:
            window.close()
            return None


def fileSelectorForm(buttonName : str = "Submit", windowTitle : str = 'Select File', chooseText : str = "Choose a file: ", file_types=(("JSON Files", "*.json"),("YAML Files", "*.yaml"),)):

    layout = [[sg.Text(chooseText), sg.Input(key="-IN2-", change_submits=True), sg.FileBrowse(key="-IN-", file_types=file_types)],
              [sg.T(""), sg.Button(" "+buttonName+" "), sg.Button(" Cancel ")]]

    window = sg.Window(windowTitle, layout, size=(520, 70))

    while True:
        event, values = window.read()
        if event == sg.WIN_CLOSED or event == "Exit":
            window.close()
            return None
        elif buttonName in event:
            window.close()
            return values["-IN-"]
        elif "Cancel" in event:
            window.close()
            return None


def fileDirectorySelectorForm(buttonName : str = "Submit", windowTitle : str = 'Select a file or Directory', chooseText : str = "Select", file_types=(("JSON Files", "*.json"),("YAML Files", "*.yaml"),)):

    layout = [[sg.Text(chooseText + " File" + " :         "), sg.Input(key="-IN2-", change_submits=True), sg.FileBrowse(key="-FILE-", file_types=file_types)],
              [sg.Text(chooseText + " Directory" + " : "),    sg.Input(key="-IN2-", change_submits=True), sg.FolderBrowse(key="-DIR-")],
              [sg.T(""), sg.Button(" "+buttonName+" "), sg.Button(" Cancel ")]]

    window = sg.Window(windowTitle, layout, size=(540, 100))

    while True:
        event, values = window.read()
        if event == sg.WIN_CLOSED or event == "Exit":
            window.close()
            return None
        elif buttonName in event:
            file = values["-FILE-"]
            dir  = values["-DIR-"]
            window.close()
            return file if (file.strip() != "") else dir
        elif "Cancel" in event:
            window.close()
            return None


class dataBrowserForm():

    def __init__(self, data , name = "NoName",
                 current_selection = None, index_prefix="",
                 formats_choices = formats, default_format = "Json",
                 read_only = True, height = 25, wide = 65, style="TREE"):
        self.clear()
        self.read_only      = read_only
        self.name           = name
        self.radio_choices  = formats_choices
        self.default_format = default_format
        self.height         = height
        self.wide           = wide
        self.repos          = data  # List Data Structure (RepositoryStore - with a Name)
        self.dico           = data  # Dict Data Structure (SuperDict)
        self.style          = style # TREE or LIST
        if (isinstance(data,list)):
            self.style          = "LIST" # TREE or LIST
        if (isinstance(data,dict)):
            self.style          = "TREE" # TREE or LIST
        self.index_prefix   = index_prefix # For list items
        if (isinstance(data,ut.RepositoryStore)):
            self.dico    = ut.SuperDict(data.getAsData())
            if (self.name): self.dico.setName(self.name)
            else:           self.dico.setName(data.getStoreName())
            self.repos = ut.RepositoryStore(storeName=self.dico.getName(), data=self.dico.getAsData(), index_prefix=index_prefix)
        elif (isinstance(data,ut.SuperDict)):
            self.dico  = data
            if (self.name): self.dico.setName(self.name)
            self.repos = ut.RepositoryStore(storeName=self.dico.getName(), data=self.dico.getAsData(), index_prefix=index_prefix)
        elif (isinstance(data,str)):
            self.dico  = ut.SuperDict(ut.to_dict(data))
            if (self.name): self.dico.setName(self.name)
            self.repos = ut.RepositoryStore(storeName=self.dico.getName(), data=self.dico.getAsData(), index_prefix=index_prefix)
        elif (isinstance(data,dict)):
            self.dico  = ut.SuperDict(data)
            if (self.name): self.dico.setName(self.name)
            self.repos = ut.RepositoryStore(storeName=self.dico.getName(), data=self.dico.getAsData(), index_prefix=index_prefix)
        elif (isinstance(data,list)):
            self.dico  = ut.SuperDict(data, name=name)
            self.repos = ut.RepositoryStore(storeName=self.name, data=data, index_prefix=index_prefix)
        self.sname          = self.name  # self.repos.getStoreName()
        self.names          = self.repos.getNames()
        self.current        = current_selection
        self.payload        = "-"+default_format+"-"
        self.current_event  = ""
        self.current_values = None
        self.treedata       = sg.TreeData()
        self.loadItem(current_selection)

    def clear(self):
        self.current     = None
        self.item        = None
        self.display     = None
        self.name        = ""
        self.description = ""
        self.source      = ""

    def loadItem(self,current_selection=None):
        if (current_selection!=None):
            self.current = current_selection
        logger.info("Loading " + str(self.current) + " in " + self.payload.replace("-", ""))
        if (self.style=="TREE") and (self.current):
            self.item        = self.dico.get(self.current)
            self.display     = self.current
            self.name        = self.dico.getName(key=self.current,default=self.current.split('/')[-1])
            self.description = self.dico.getDescription(key=self.current,default="N/D")
            self.source      = self.dico.getSource(key=self.current,default=self.current)
        elif (self.current): # LIST
            self.item        = self.repos.getByIndex(self.current.replace(self.index_prefix,""))
            self.display     = self.current
            self.name        = self.current
            self.description = self.repos.getDescription(self.current)
            self.source      = self.repos.getSource(self.current)
        else: # None
            self.item        = None
            self.display     = None
            self.name        = ""
            self.description = ""
            self.source      = ""
        prefix=""
        if (self.current == None) : return
        if (self.current == "") : return
        if (self.current == "/") : return
        # setting the Selected Item as a Dict
        _class =  self.dico.get(self.current).__class__.__name__
        if (_class in ["dict"]): # Dict
            logger.info("Dict : "+self.current)
            self.item =  self.item
            return
        if (_class in ["list"]): # list (calculate a key - with prefix)
            logger.info("List : "+self.current)
            self.item =  { prefix + self.current.split('/')[-1] : self.item }
            return
        if (_class in ["str","bool","int","float"]): # Leaf  (calculate a key - with prefix)
            if (len(self.current.split('/'))>=2):
                prefix = re.sub("/[^\/]*$", "", self.current)
                if self.dico.isList(prefix):
                    logger.info("Member of a List : " + self.current)
                    self.item = { self.current.split('/')[-2]+" "+ self.current.split('/')[-1] : self.item}
                    return
            logger.info("Leaf : "+self.current)
            self.item = { self.current.split('/')[-1] : self.item }
            return

    def updateTreeData(self, parent='', dico=None):
        if (dico==None):
            dico = self.dico
        if (isinstance(dico,ut.SuperDict)):
            dico = dico.getAsData()
        if (parent == None) or (parent == ''): # root
            prefix = ''
            self.treedata = sg.TreeData()
        else:
            prefix = parent + '/'
        if (isinstance(dico, dict)):
            for key in dico.keys():
                if key.startswith("__"): continue
                it = dico[key]
                full_key   = prefix+str(key)
                leaf_key   = str(key)
                parent_key = parent.split('/')[-1]
                if isinstance(it, dict):  # Sub Dict = Folder, add folder and recurse
                    self.treedata.Insert(parent, key=full_key, text=leaf_key, values=["{ \/ }"], icon=treeBrowserForm.folder_icon)
                    self.updateTreeData(prefix + str(key), it)
                elif isinstance(it, list):  # Sub List = Folder, add folder and recurse
                    self.treedata.Insert(parent, key=full_key, text=leaf_key, values=["[ \/ ]"], icon=treeBrowserForm.folder_icon)
                    self.updateTreeData(prefix + str(key), it)
                else: # Leaf with basic type
                    # Insert(parent, key, text, values, icon=None)
                    self.treedata.Insert(parent, key=full_key, text=leaf_key, values=[str(dico[key])], icon=treeBrowserForm.file_icon)
        if (isinstance(dico, list)):
            for idx, it in enumerate(dico):
                key = str(idx)
                it = dico[idx]
                full_key   = prefix+str(key)
                leaf_key   = str(str(idx+1))
                parent_key = parent.split('/')[-1]
                if isinstance(it, dict):  # List Item is a folder, add folder and recurse
                    name = ut.SuperDict(it).getName()
                    if (not name) or (name == "NoName"): name = parent_key+" "+leaf_key
                    self.treedata.Insert(parent, key=full_key, text=name, values=["{ \/ }"], icon=treeBrowserForm.folder_icon)
                    self.updateTreeData(prefix + str(key), it)
                elif isinstance(it, list):  # List Item is a folder, add folder and recurse
                    self.treedata.Insert(parent, key=full_key, text=parent_key+" "+leaf_key, values=["[ \/ ]"], icon=treeBrowserForm.folder_icon)
                    self.updateTreeData(prefix + str(key), it)
                else: # Leaf with basic type
                    self.treedata.Insert(parent, key=full_key, text=parent_key+" "+leaf_key, values=[str(dico[idx])], icon=treeBrowserForm.file_icon)

    def update(self, current_name = None):
        if (current_name):
            self.loadItem(current_name)
        self.window['-RULE_NAME-'].Update(self.name)
        self.window['-COMMENT-'].Update(self.description)
        self.window['-SOURCE-'].Update(self.source)
        if (not self.display): self.display = self.name
        if (self.read_only):
            # self.window['-SELECT-'].Update("Browse "+self.display)
            pass
        else:
            self.window['-SELECT-'].Update("Select "+self.display)
        self.window['-STATUS-'].Update(" " + self.display + " ")
        self.window.Title = self.name
        self.window[self.payload].Update(value=True) # Radio Button
        ### Selected Element
        if (self.payload=="-Json-"):
            self.window['-PAYLOAD-'].Update(ut.SuperDict(self.item).clean().json())
        elif (self.payload=="-Flat-"):
            self.window['-PAYLOAD-'].Update(ut.SuperDict(self.item,name = self.name).clean().flattenedText())
        elif (self.payload=="-Context-"):
            self.window['-PAYLOAD-'].Update(ut.SuperDict(self.item).clean().flattenedText(key_prefix="context[\"",key_suffix="\"]",key_value_sep = " == "))
        elif (self.payload=="-Description-"):
            self.window['-PAYLOAD-'].Update(ut.SuperDict(self.item).clean().flattenedText(key_prefix="",key_suffix="",val_prefix="",val_suffix="",key_value_sep=" : "))
        elif (self.payload=="-Yaml-"):
            self.window['-PAYLOAD-'].Update(ut.SuperDict(self.item).clean().yaml())
        elif (self.payload=="-Variables-"):
            self.window['-PAYLOAD-'].Update(ut.SuperDict(self.item).clean().variables(path_sep="/",var_sep=" ,\n",key_prefix="  \"",key_suffix="\"",prefix="[\n",suffix="]"))
        ### Full Tree
        elif (self.payload=="-List-"):
            if (self.style=="TREE"):
                self.window['-PAYLOAD-'].Update(str(self.dico.getKeyList(self.current)))
            else:
                self.window['-PAYLOAD-'].Update(str(self.repos.getKeyList(self.current)))
        elif (self.payload=="-Format-"):
            self.window['-PAYLOAD-'].Update(str(self.repos.format(self.current)))
        elif (self.payload=="-Conditions-"):
            self.window['-PAYLOAD-'].Update(ut.getConditionsList2Text(self.repos.getList(),or_sep=" \nOR "))
        elif (self.payload=="-Repository-"):
            self.window['-PAYLOAD-'].Update(ut.to_json(self.repos.getAsData()))
        elif (self.payload in ["-Content-","-Python-"]):
            if self.item and "Content" in self.item :
                content = ut.json_decode_multiline(self.item["Content"])
                self.window['-PAYLOAD-'].Update(content)
            else:
                self.window['-PAYLOAD-'].Update(str(self.item))

    def layout(self):
        font   = 10
        height = self.height
        col_0 = 25 ; col_1 = 6 ; col_2 = self.wide
        if (self.read_only):   color = None ;                cancel_text = 'Close'  ; select_text = 'Select'
        else:                  color = ('black', 'white') ;  cancel_text = 'Cancel' ; select_text = 'Select'
        # sg.Text('Payload', size=(col_1, 1)),
        col = [[sg.Text('Name :',     size=(col_1, 1)),  sg.InputText(key='-RULE_NAME-',  default_text=self.name,        size=(col_2, 1), disabled=True)],
               [sg.Text('Value : ',   size=(col_1, 1)),  sg.InputText(key='-COMMENT-',    default_text=self.description, size=(col_2, 1), disabled=True)],
               [sg.Text('Path :',     size=(col_1, 1)),  sg.InputText(key='-SOURCE-',     default_text=self.source,      size=(col_2, 1), disabled=True)],
               [sg.Radio(text, 1,enable_events = True, key="-"+text+"-") for text in self.radio_choices ],
               [sg.Multiline(default_text=self.name, size=(col_2 + col_1 - 8  , height -5 ), font=("Courier", font), key='-PAYLOAD-', disabled=True)]]
        if (self.read_only):
            buttons = [sg.Button(cancel_text, key="-CANCEL-", size=(col_0+2, 1), button_color=color)]
        else:
            buttons = [sg.Button(select_text, key="-SELECT-", size=(col_0 + 18, 1), button_color=color), sg.Text('', size=(0, 1)),
                       sg.Button(cancel_text, key="-CANCEL-", size=(col_0 + 2, 1), button_color=color)]
        status  = [sg.StatusBar("Status", key="-STATUS-",tooltip=" Current Key Path ",size=(col_0+col_1+col_2+15,1))]
        if (self.style == "TREE"): # headings=['Value']
            return [[sg.Tree( data=self.treedata, show_expanded=False,
                              headings=['Value'], col_widths=[20], auto_size_columns=True, num_rows=height, col0_width=col_0,
                              key='-TREE-', enable_events=True,
                              header_background_color=sg.theme_element_background_color(),
                              header_text_color=sg.theme_element_text_color(),
                              # font=("Courier", font),
                              # header_font=("Courier", font),
                              tooltip=self.repos.getStoreName()), sg.Column(col)] , buttons , status]
        else:
            return [[sg.Listbox(values=(self.names),
                                enable_events=True, key="-LIST-",
                                font=("Courier", font),
                                size=(col_0, height),
                                tooltip=self.repos.getStoreName()), sg.Column(col)] , buttons , status]

    def run(self):
        if (self.read_only):  title = 'Browsing '  + str(self.sname)
        else:                 title = 'Selecting ' + str(self.sname)
        if (self.style=="TREE"):
            self.updateTreeData()
        self.window = sg.Window(title, self.layout(),finalize=True,keep_on_top=True)
        self.update()

        # Event Loop
        while True:
            if (self.current_event!= "Timeout"):
                logger.info("Event   : " + str(self.current_event) + " - " + str("Done"))
            self.current_event, self.current_values = self.window.Read(timeout=100,timeout_key="Timeout") # in ms
            if self.current_event is None: break
            if self.current_event == "Timeout": continue
            logger.info("Event : " + str(self.current_event) + " >> Values : " + str(self.current_values))

            # Selecting in List View
            if (self.current_event == "-LIST-"):
                if (len(self.current_values["-LIST-"])==0): return
                self.loadItem(self.current_values["-LIST-"][0])

            # Selecting in Tree View
            if (self.current_event == "-TREE-"):
                if (len(self.current_values["-TREE-"])==0): return
                self.loadItem(self.current_values["-TREE-"][0])

            ### Radio Buttons Formats
            if (self.current_event.replace("-","") in formats):
                self.payload = self.current_event
                if (self.current_event in ["-Conditions-","-Python-","-Repository-"]):
                    self.display = self.repos.getStoreName()
                else: self.display = None
                self.loadItem()

            if (self.current_event == "-SELECT-"):
                logger.info("Selected : " + str(self.current) )
                self.window.close()
                return self.current

            if (self.current_event == "-CANCEL-"):
                self.current = None
                logger.info("Canceled : " + str(self.current) )
                self.window.close()
                return self.current

            self.update()
            continue

        logger.info("Closed : " + str(None))
        self.window.close()
        return None


class treeBrowserForm():

    # Base64 versions of images of a folder and a file. PNG files (may not work with PySimpleGUI27, swap with GIFs)
    folder_icon = b'iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAACXBIWXMAAAsSAAALEgHS3X78AAABnUlEQVQ4y8WSv2rUQRSFv7vZgJFFsQg2EkWb4AvEJ8hqKVilSmFn3iNvIAp21oIW9haihBRKiqwElMVsIJjNrprsOr/5dyzml3UhEQIWHhjmcpn7zblw4B9lJ8Xag9mlmQb3AJzX3tOX8Tngzg349q7t5xcfzpKGhOFHnjx+9qLTzW8wsmFTL2Gzk7Y2O/k9kCbtwUZbV+Zvo8Md3PALrjoiqsKSR9ljpAJpwOsNtlfXfRvoNU8Arr/NsVo0ry5z4dZN5hoGqEzYDChBOoKwS/vSq0XW3y5NAI/uN1cvLqzQur4MCpBGEEd1PQDfQ74HYR+LfeQOAOYAmgAmbly+dgfid5CHPIKqC74L8RDyGPIYy7+QQjFWa7ICsQ8SpB/IfcJSDVMAJUwJkYDMNOEPIBxA/gnuMyYPijXAI3lMse7FGnIKsIuqrxgRSeXOoYZUCI8pIKW/OHA7kD2YYcpAKgM5ABXk4qSsdJaDOMCsgTIYAlL5TQFTyUIZDmev0N/bnwqnylEBQS45UKnHx/lUlFvA3fo+jwR8ALb47/oNma38cuqiJ9AAAAAASUVORK5CYII='
    file_icon   = b'iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAACXBIWXMAAAsSAAALEgHS3X78AAABU0lEQVQ4y52TzStEURiHn/ecc6XG54JSdlMkNhYWsiILS0lsJaUsLW2Mv8CfIDtr2VtbY4GUEvmIZnKbZsY977Uwt2HcyW1+dTZvt6fn9557BGB+aaNQKBR2ifkbgWR+cX13ubO1svz++niVTA1ArDHDg91UahHFsMxbKWycYsjze4muTsP64vT43v7hSf/A0FgdjQPQWAmco68nB+T+SFSqNUQgcIbN1bn8Z3RwvL22MAvcu8TACFgrpMVZ4aUYcn77BMDkxGgemAGOHIBXxRjBWZMKoCPA2h6qEUSRR2MF6GxUUMUaIUgBCNTnAcm3H2G5YQfgvccYIXAtDH7FoKq/AaqKlbrBj2trFVXfBPAea4SOIIsBeN9kkCwxsNkAqRWy7+B7Z00G3xVc2wZeMSI4S7sVYkSk5Z/4PyBWROqvox3A28PN2cjUwinQC9QyckKALxj4kv2auK0xAAAAAElFTkSuQmCC'

    def __init__(self, dico : ut.SuperDict, read_only=True):
        self.read_only = read_only
        self.current   = None
        self.dico          = dico
        self.treedata = sg.TreeData()
        if (isinstance(dico,ut.RepositoryStore)):
            self.dico   = dico.getAsData()
        elif (isinstance(dico,ut.SuperDict)):
            self.dico = dico
        elif (isinstance(dico, str)):
            self.dico = ut.SuperDict(ut.to_dict(dico))
        elif (isinstance(dico, list)):
            self.dico = ut.SuperDict(ut.to_dict(ut.to_json(dico)))
        elif (isinstance(dico,dict)):
            self.dico = ut.SuperDict(dico)
        self.current_event  = ""
        self.current_values = None

    def loadItem(self,current_name):
        self.current = current_name
        logger.info("Loading Item : "+self.current)

    def update(self, current_name= None):
        if (current_name):
            self.loadItem(current_name)
        if (self.current != None):
            self.window.Element('-TITLE-').Update(self.current)
            if (not self.read_only):
                self.window.Element('-SELECT-').Update(str(self.dico.get(self.current)))

    def layout(self, title="Data Browser"):
        num_rows     = 20
        col0_width   = 30
        if (self.read_only):
            clr = None ;  cancel_text = 'Close' ; select_text = 'OK'
        else:
            clr = ('black', 'white') ;  cancel_text = 'Cancel' ;  select_text = 'Select'
        layout = [[sg.Text(title, key="-TITLE-", size=(30, 1))],
                  [sg.Tree(data=self.treedata,
                       headings=['Value', ],
                       auto_size_columns=True,
                       num_rows=num_rows,
                       col0_width=col0_width,
                       key='-TREE-',
                       show_expanded=False,
                       enable_events=True),
                   ],
                  [sg.Button(select_text, key="-OK-"    , size=(10, 1), button_color=clr),
                   sg.Button(cancel_text, key="-CANCEL-", size=(10, 1), button_color=clr),
                   sg.Text(key="-SELECT-", size=(30, 1) )]]
        return layout

    def updateTreeData(self, parent="", dico=None):
        if (dic == None):
            dico = self.dico
        if (isinstance(dico,ut.SuperDict)):
            dico = dico.getAsData()
        if (parent == ''):
            prefix = ''
            self.treedata = sg.TreeData()
        else:
            prefix = parent + '/'
        if (isinstance(dico, dict)):
            for key in dico.keys():
                it = dico[key]
                if isinstance(it, dict):  # if it's a folder, add folder and recurse
                    self.treedata.Insert(parent, prefix + str(key), key, values=["{ \/ }"], icon=treeBrowserForm.folder_icon)
                    self.updateTreeData(prefix + str(key), it)
                elif isinstance(it, list):  # if it's a folder, add folder and recurse
                    self.treedata.Insert(parent, prefix + str(key), key, values=["[ \/ ]"], icon=treeBrowserForm.folder_icon)
                    self.updateTreeData(prefix + str(key), it)
                else:
                    # Insert(parent,    key,    text,     values,    icon=None)
                    self.treedata.Insert(parent, prefix + str(key), key, values=[str(dico[key])], icon=treeBrowserForm.file_icon)
        if (isinstance(dico, list)):
            for idx, it in enumerate(dico):
                key = str(idx)
                it = dico[idx]
                if isinstance(it, dict):  # if it's a folder, add folder and recurse
                    self.treedata.Insert(parent, prefix + str(key), key, values=["{ \/ }"], icon=treeBrowserForm.folder_icon)
                    self.updateTreeData(prefix + str(key), it)
                elif isinstance(it, list):  # if it's a folder, add folder and recurse
                    self.treedata.Insert(parent, prefix + str(key), key, values=["[ \/ ]"], icon=treeBrowserForm.folder_icon)
                    self.updateTreeData(prefix + str(key), it)
                else:
                    self.treedata.Insert(parent, prefix + str(key), key, values=[str(dico[idx])], icon=treeBrowserForm.file_icon)

    def run(self):
        self.updateTreeData()
        self.window = sg.Window("Data Browser", self.layout(title="Data Browser"),finalize=True)
        self.update()

        # The Event Loop
        while True:
            if (self.current_event!= "Timeout"):
                logger.info("Event   : " + str(self.current_event) + " - " + str("Done"))
            self.current_event, self.current_values = self.window.Read(timeout=100,timeout_key="Timeout") # in ms
            if self.current_event is None: break
            if self.current_event == "Timeout": continue
            logger.info("Event : " + str(self.current_event) + " >> Values : " + str(self.current_values))

            if (self.current_event == "-TREE-"):
                if (len(self.current_values["-TREE-"])==0): return
                current = self.current_values["-TREE-"][0]
                logger.info("Loading " + str(current))
                self.loadItem(current)

            if (self.current_event == "-CANCEL-"):
                self.current = None
                logger.info("Canceled : " + str(self.current) )
                self.window.close()
                return self.current

            self.update()
            continue

        logger.info("Closed : " + str(None))
        self.window.close()
        return None


def aboutPopup(configuration_file=None):
    text = "Amdocs Exposure Platform (c) Amdocs Openet\n  Contact: bheuse@amdocs.com"
    if (configuration_file):
        text = text + "\n\n  Configuration File:\n" + configuration_file
    sg.PopupScrolled(text, title="About ...", size=(35, 3))
    return text


def saveForEditor(content,fileName):
    content  = content.replace('\r\n', '\n')
    ext      = ut.get_extension(fileName)
    naked    = ut.get_nakedname(fileName)
    filepath = tempfile.gettempdir() + os.sep + naked + "." + ext.replace(".","")
    logger.info("save For Editor in File : "+filepath)
    ut.saveFileContent(content,filepath)
    return filepath


def openEditor(application, content,fileName):
    filepath = saveForEditor(content,fileName)
    editor   = settingsForm.getSettings(application=application, item="Editor")
    cmd      = editor+" "+ filepath
    if platform.system() == 'Darwin':  # macOS
        subprocess.call(('open', filepath))
    elif platform.system() == 'Windows':  # Windows
        logger.info("Editor for Windows : " + cmd)
        #os.startfile(cmd)
        subprocess.run(cmd)
    else:  # linux variants
        subprocess.call(('xdg-open', filepath))
    return filepath


if __name__ == '__main__':
    # wd = settingsForm(application="test",title="Test Application")
    # wd.manageSettings()
    dir = fileSelectorForm()
    dir = fileDirectorySelectorForm()
    print(dir)

