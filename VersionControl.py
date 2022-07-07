import datetime
import logging
import re
import unittest

from typing import Optional

import Util as ut

logging.basicConfig(format='%(levelname)s:%(name)s:%(message)s', level=logging.INFO)
logger = logging.getLogger('VersionControl')

VC_CREATED = "Created"
VC_UPDATED = "Updated"
VC_DELETED = "Deleted"


class VersionControl:

    def __init__(self, vc: dict = None, comment: str = "UNDEFINED", version: str = "0",
                       filename: str = None, fileExt: str = ".json", fType: str = "UNDEFINED",
                       tag: str = "UNDEFINED", pID: str = "UNDEFINED",
                       author: str = "UNDEFINED", source: str = "UNDEFINED",
                       timestamp: str = None, status: str = VC_CREATED):
        self.versionControl = dict()
        if vc != None:
            self.set(vc)
            return
        else:
            self.set()
        self.setStatus(status)
        self.setVersion(version)
        self.setComment(comment)
        self.setType(fType)
        self.setTag(tag)
        self.setID(pID)
        self.setFileName(filename)
        self.setExt(fileExt)
        self.setTimeStamp(timestamp)
        self.setAuthor(author)
        self.setSource(source)

    def set(self, pDict: dict = None):
        if pDict == None :
            pDict = dict()
        if isinstance(pDict, VersionControl):
            pDict = pDict.versionControl
        if isinstance(pDict, ut.SuperDict):
            pDict = pDict.getAsData()
        if "VersionControl" in pDict:
            self.versionControl = pDict
        else:
            self.versionControl = dict()
            self.versionControl["VersionControl"] = pDict
        return self.versionControl

    def getField(self, field: str):
        return self.versionControl["VersionControl"][field]

    def setField(self, field: str, value):
        self.versionControl["VersionControl"][field] = value

    def setTag(self, tag):
        return self.setField("Tag", tag)

    def getTag(self):
        return self.getField("Tag")

    def setStatusCreated(self):
        return self.setField("Status", VC_CREATED)

    def setStatusUpdated(self):
        return self.setField("Status", VC_UPDATED)

    def setStatusDeleted(self):
        return self.setField("Status", VC_DELETED)

    def isDeleted(self):
        return (self.getField("Status") == VC_DELETED)

    def setStatus(self, status):
        return self.setField("Status", status)

    def setComment(self, comment):
        return self.setField("Comment", comment)

    def getComment(self):
        return self.getField("Comment")

    def setType(self, fType):
        return self.setField("Type", fType)

    def getType(self):
        return self.getField("Type")

    def setID(self, pID):
        return self.setField("ID", pID)

    def getID(self):
        return self.getField("ID")

    def setExt(self, ext):
        return self.setField("FileExt", ext)

    def getExt(self):
        return self.getField("FileExt")

    def setFileName(self, filename):
        return self.setField("FileName", filename)

    def getFileName(self):
        return self.getField("FileName")

    def setTimeStamp(self, timestamp = None):
        timestamp = timestamp if (timestamp != None) else datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.setField("Timestamp", timestamp)

    def getTimeStamp(self):
        return self.getField("Timestamp")

    def setSource(self, source):
        return self.setField("Source", source)

    def getSource(self):
        return self.getField("Source")

    def setAuthor(self, author):
        return self.setField("Author", author)

    def getAuthor(self):
        return self.getField("Author")

    def setVersion(self, version):
        return self.setField("Version", version)

    def getVersion(self):
        return self.getField("Version")

    def incVersion(self):
        ver = self.getField("Version")
        try:
            HEAD = re.sub("[0-9]*$", "", ver)
            EXT = re.sub(HEAD, "", ver)
            if (EXT == ''): EXT = '0'
            new_ver = HEAD + '{:0>{}}'.format(str(int(EXT)+1), len(EXT))
        except:
            logger.exception("Cannot Increment VersionControl Version : "+ver)
            new_ver = ver
        self.setField("Version", new_ver)
        return new_ver

    def asDict(self):
        return self.versionControl

    def asJson(self):
        return ut.to_json(self.asDict())

    def asYaml(self):
        return ut.to_yaml(self.asDict())

    def asPythonComment(self):
        return "\n'''VersionControl\n" + ut.to_json(self.asDict()) + "\n'''\n"

    def asMakoComment(self):
        return "\n<%doc>VersionControl\n" + ut.to_json(self.asDict()) + "\n</%doc>\n"

    def asXMLComment(self):
        return "\n<!--VersionControl\n" + ut.to_json(self.asDict()) + "\n-->\n"


def isFileFormat(filePath: str, fFormat: str):
    return (fileFormatExt(ut.get_extension(filePath)) == fFormat)


def fileFormat(filePath: str):
    return fileFormatExt(ut.get_extension(filePath))


def fileFormatExt(ext) -> str :  # File Extension of Format
    ext = ext.lower()
    if not ext.startswith("."): ext = "."+ext
    if ext in ut.JSON_FILES: return ut.JSON_FILE
    if ext in ut.YAML_FILES: return ut.YAML_FILE
    if ext in ut.MAKO_FILES: return ut.MAKO_FILE
    if ext in ut.PY_FILES:   return ut.PY_FILE
    if ext in ut.XML_FILE:   return ut.XML_FILES
    if ext in ut.HTML_FILE:  return ut.HTML_FILES
    if ext in ut.JPG_FILE:   return ut.JPG_FILES
    if ext in ut.CSV_FILE:   return ut.CSV_FILES
    if ext in ut.ZIP_FILE:   return ut.ZIP_FILES

###
### Content Based
###


def getVCfromContent(fFormat, content: str) -> Optional[VersionControl]:
    if (fFormat == ut.JSON_FILE) or (fFormat == ut.YAML_FILE) :
        try:
            data = ut.loadDataContent(content)
            if (data == None): return None
            if "VersionControl" in data:
                return VersionControl(data["VersionControl"])
            return None
        except:
            logger.exception("Error Fetching Version Control in Format [" + str(fFormat) + "] Content : \n" + str(content))
            return None
    try:
        vc = ""
        if   (fFormat == ut.MAKO_FILE): vc = ut.find_between(content, "<%doc>VersionControl", "</%doc>")
        elif (fFormat == ut.PY_FILE):   vc = ut.find_between(content, "\'\'\'VersionControl", "\'\'\'")
        elif (fFormat == ut.XML_FILE):  vc = ut.find_between(content, "<!--VersionControl", "-->")
        elif (fFormat == ut.HTML_FILE): vc = ut.find_between(content, "<!--VersionControl", "-->")
        if (vc == None) or (vc == ""): return None
        vc.strip()
        logger.info("VersionControl Extract : " + vc)
        data = ut.loadJsonContent(vc)
        if "VersionControl" in data:
            return VersionControl(data)
        if "Version" in data:
            return VersionControl(data)
        return None
    except:
        logger.exception("Error Fetching Version Control in Format ["+str(fFormat)+"] Content : \n" + content)
        return None


def getContentfromContent(fFormat, content: str) -> str:
    if (fFormat == ut.JSON_FILE) or (fFormat == ut.YAML_FILE) :
        try:
            data = ut.loadDataContent(content)
            if (data == None): return content
            if "VersionControl" in data :
                del data["VersionControl"]
            if (fFormat == ut.JSON_FILE): return ut.to_json(data)
            if (fFormat == ut.YAML_FILE): return ut.to_yaml(data)
            return content
        except:
            logger.exception("Error Fetching Version Control in content : " + str(content))
            return content
    try:
        if   (fFormat == ut.MAKO_FILE): content = ut.remove_between(content, "\n<%doc>VersionControl", "</%doc>\n")
        elif (fFormat == ut.PY_FILE):   content = ut.remove_between(content, "\n\'\'\'VersionControl", "\'\'\'\n")
        elif (fFormat == ut.XML_FILE):  content = ut.remove_between(content, "\n<!--VersionControl", "-->\n")
        elif (fFormat == ut.HTML_FILE): content = ut.remove_between(content, "\n<!--VersionControl", "-->\n")
        else:  content = content
        return content
    except:
        logger.exception("Error Removing Version Control in Format ["+str(fFormat)+"] Content : \n" + str(content))
        return content


def setVCinContent(fFormat, content: str, vc: VersionControl):
    content = getContentfromContent(fFormat, content)
    if (fFormat == ut.JSON_FILE) or (fFormat == ut.YAML_FILE) :
        try:
            data = ut.loadDataContent(content)
            if (data == None): return content
            if "VersionControl" in data :
                del data["VersionControl"]
            data["VersionControl"] = vc.versionControl["VersionControl"]
            if (fFormat == ut.JSON_FILE): return ut.to_json(data)
            if (fFormat == ut.YAML_FILE): return ut.to_yaml(data)
            return None
        except:
            logger.exception("Error Fetching Version Control in content : " + str(content))
            return content
    try:
        if   (fFormat == ut.MAKO_FILE): content = content.strip() + vc.asMakoComment()
        elif (fFormat == ut.PY_FILE):   content = content.strip() + vc.asPythonComment()
        elif (fFormat == ut.XML_FILE):  content = content.strip() + vc.asXMLComment()
        elif (fFormat == ut.HTML_FILE): content = content.strip() + vc.asXMLComment()
        else:  content = content
        return content
    except:
        logger.exception("Error Setting Version Control in Format ["+str(fFormat)+"] Content : \n" + content)
        return content

###
### Format Agnostic Functions
###


### Save Content with VC in File
def saveVcContentInFile(vc: VersionControl, content, filePath: str) -> VersionControl:  # Save File with VC
    if (isinstance(content, dict)):
        fFormat = fileFormat(filePath)
        if (fFormat == ut.JSON_FILE): content = ut.to_json(content)
        if (fFormat == ut.YAML_FILE): content = ut.to_yaml(content)
    content = setVCinContent(fileFormat(filePath), content, vc)
    ut.saveFileContent(content, filePath)
    return vc


### Update with VC in File
def setVcInFile(vc: VersionControl, filePath: str) -> VersionControl:
    return saveVcContentInFile(vc, ut.loadFileContent(filePath), filePath)


### Get Content From File, w/o VC
def getFileContent(filePath: str, withVC = False) -> str:  # File Content without VC
    content = ut.loadFileContent(filePath)
    if (withVC):
        return content
    else:
        return getContentfromContent(fileFormat(filePath), content)


### Get VC From File
def getFileVc(filePath: str) -> VersionControl:  # Get VC from File
    content = ut.loadFileContent(filePath)
    return getVCfromContent(fileFormat(filePath), content)


### Get Details about File
def getFileData(filePath: str) -> dict:
    content = ut.loadFileContent(filePath)
    content = getContentfromContent(fileFormat(filePath), content)
    data    = ut.loadDataContent(content)
    vc      = getVCfromContent(fileFormat(filePath), content)
    fFormat = fileFormat(filePath)
    dc = dict()
    dc["FilePath"]   = filePath
    dc["FileName"]   = ut.get_nakedname(filePath)
    dc["FileExt"]    = ut.get_extension(filePath)
    dc["FileFormat"] = fFormat
    dc["VC"]         = vc
    dc["Content"]    = content
    dc["Data"]       = data
    return dc


###
### Unit Test
###


class TestVersionControlMethods(unittest.TestCase):

    def test_VersionControl(self):
        vc = VersionControl(comment="THE COMMENT", version="0", filename="FILE", fType="TYPE", pID="ID", tag="TAG", author="AUTHOR", source="SOURCE")
        # print(vc.asYaml())
        # print(vc.asJson())
        # print(vc.asMakoComment())
        # print(vc.asPythonComment())
        vc.setStatusCreated()
        self.assertEqual(vc.getField("Status"), VC_CREATED)
        self.assertFalse(vc.isDeleted())
        vc.setStatusUpdated()
        self.assertFalse(vc.isDeleted())
        self.assertEqual(vc.getField("Status"), VC_UPDATED)
        vc.setStatusDeleted()
        self.assertTrue(vc.isDeleted())
        self.assertEqual(vc.getField("Status"), VC_DELETED)
        self.assertEqual(vc.getAuthor(), "AUTHOR")
        vc.setAuthor("NewAUTHOR")
        self.assertEqual(vc.getAuthor(), "NewAUTHOR")
        self.assertEqual(vc.getSource(), "SOURCE")
        vc.setSource("NewSOURCE")
        self.assertEqual(vc.getSource(), "NewSOURCE")
        self.assertEqual(vc.getTag(), "TAG")
        vc.setTag("New")
        self.assertEqual(vc.getTag(), "New")
        self.assertEqual(vc.getComment(), "THE COMMENT",)
        vc.setComment("New COMMENT")
        self.assertEqual(vc.getComment(), "New COMMENT")
        self.assertEqual(vc.getVersion(), "0")
        vc.incVersion()
        self.assertEqual(vc.getVersion(), "1")
        vc.incVersion()
        self.assertEqual(vc.getVersion(), "2")
        vc.setVersion("345")
        self.assertEqual(vc.getVersion(), "345")
        vc.incVersion()
        self.assertEqual(vc.getVersion(), "346")
        vc.setVersion("TT.")
        vc.incVersion()
        self.assertEqual(vc.getVersion(), "TT.1")
        vc.incVersion()
        self.assertEqual(vc.getVersion(), "TT.2")
        self.assertEqual(vc.getID(), "ID")
        self.assertEqual(vc.getType(), "TYPE")
        self.assertEqual(vc.getExt(), ".json")
        vc.setExt(".rule")
        self.assertEqual(vc.getExt(), ".rule")
        self.assertEqual(vc.getFileName(), "FILE")

        vc.setTimeStamp("TT")
        self.assertEqual(vc.getTimeStamp(), "TT")

        self.assertEqual((isFileFormat("tt.Rule", ut.PY_FILE)),   True)
        self.assertEqual((isFileFormat("tt.mako", ut.MAKO_FILE)), True)
        self.assertEqual((isFileFormat("tt.yaml", ut.YAML_FILE)), True)
        self.assertEqual((isFileFormat("tt.py",   ut.PY_FILE  )), True)
        self.assertEqual((isFileFormat("tt.yaml", ut.JSON_FILE)), False)
        self.assertEqual((isFileFormat("tt.RuLE", ut.MAKO_FILE)), False)
        self.assertEqual((isFileFormat("tt.json", ut.YAML_FILE)), False)
        self.assertEqual((isFileFormat("tt.yy",   ut.PY_FILE  )), False)

    def test_PyFile(self):
        the_content = "import os\nprint('OK')\n"
        the_file    = "Test_VersionControl.py"
        the_type    = "Python"

        vc = VersionControl(comment="THE COMMENT PY", version="VERSIONPY", filename="FILEPY", fType=the_type, pID="IDPY", fileExt=ut.get_extension(the_file))
        self.assertEqual(vc.getVersion(), "VERSIONPY")
        self.assertEqual(vc.getID(), "IDPY")
        self.assertEqual(vc.getType(), the_type, the_file)
        self.assertEqual(vc.getExt(), ut.get_extension(the_file), the_file)

        saveVcContentInFile(vc, the_content, the_file)
        self.assertEqual(ut.safeFileExist(the_file), True, the_file)

        content1 = ut.loadFileContent(the_file)
        vc1 = getVCfromContent(fileFormat(the_file), content1)
        self.assertDictEqual(vc1.versionControl, vc.versionControl, the_file)

        vc2 = VersionControl(getFileVc(the_file).asDict())
        self.assertDictEqual(vc2.versionControl, vc.versionControl, the_file)

        content3 = getFileContent(the_file)
        self.assertEqual(content3.strip(), the_content.strip())

        data = getFileData(the_file)
        self.assertEqual(data["Content"].strip(),  the_content.strip())
        self.assertEqual(data["FileName"].strip(), "Test_VersionControl")
        self.assertEqual(data["FileExt"].strip(),  ".py")

        saveVcContentInFile(vc1, data["Content"], the_file)
        content1 = ut.loadFileContent(the_file)
        vc4 = getVCfromContent(fileFormat(the_file), content1)
        self.assertDictEqual(vc1.versionControl, vc4.versionControl, the_file)

        vc.setTag("TOTO")
        setVcInFile(vc, the_file)
        vc4 = getFileVc(the_file)
        self.assertDictEqual(vc4.versionControl, vc.versionControl, the_file)

        ut.safeFileRemove(the_file)

    def test_MakoFile(self):
        the_content = "Hello $(Toto)\nYour Name is : ${Name}\n"
        the_file    = "Test_VersionControl.mako"
        the_type    = "Template"

        vc = VersionControl(comment="THE COMMENT PY", version="VERSIONPY", filename="FILEPY", fType=the_type, pID="IDPY", fileExt=ut.get_extension(the_file))
        self.assertEqual(vc.getVersion(), "VERSIONPY")
        self.assertEqual(vc.getID(), "IDPY")
        self.assertEqual(vc.getType(), the_type, the_file)
        self.assertEqual(vc.getExt(), ut.get_extension(the_file), the_file)

        saveVcContentInFile(vc, the_content, the_file)
        self.assertEqual(ut.safeFileExist(the_file), True, the_file)

        content1 = ut.loadFileContent(the_file)
        vc1 = getVCfromContent(fileFormat(the_file), content1)
        self.assertDictEqual(vc1.versionControl, vc.versionControl, the_file)

        vc2 = VersionControl(getFileVc(the_file).asDict())
        self.assertDictEqual(vc2.versionControl, vc.versionControl, the_file)

        content3 = getFileContent(the_file)
        self.assertEqual(content3.strip(), the_content.strip())

        data = getFileData(the_file)
        self.assertEqual(data["Content"].strip(),  the_content.strip())
        self.assertEqual(data["FileName"].strip(), "Test_VersionControl")
        self.assertEqual(data["FileExt"].strip(),  ".mako")

        saveVcContentInFile(vc1, data["Content"], the_file)
        content1 = ut.loadFileContent(the_file)
        vc4 = getVCfromContent(fileFormat(the_file), content1)
        self.assertDictEqual(vc1.versionControl, vc4.versionControl, the_file)

        vc.setTag("TOTO")
        setVcInFile(vc, the_file)
        vc4 = getFileVc(the_file)
        self.assertDictEqual(vc4.versionControl, vc.versionControl, the_file)

        ut.safeFileRemove(the_file)

    def test_JsonFile(self):
        the_content = '{\n    "TT": "TT"\n}\n'
        the_file    = "Test_VersionControl.json"
        the_type    = "Rule"
        the_data    = ut.loadDataContent(the_content)

        vc = VersionControl(comment="THE COMMENT JS", version="VERSIONJS", filename="FILEJS", fType=the_type, pID="IDJS", fileExt=ut.get_extension(the_file))
        self.assertEqual(vc.getVersion(), "VERSIONJS")
        self.assertEqual(vc.getID(), "IDJS")
        self.assertEqual(vc.getType(), the_type, the_file)
        self.assertEqual(vc.getExt(), ut.get_extension(the_file), the_file)

        saveVcContentInFile(vc, ut.to_json(the_data), the_file)
        self.assertEqual(ut.safeFileExist(the_file), True, the_file)
        content1 = ut.loadFileContent(the_file)
        vc1 = getVCfromContent(fileFormat(the_file), content1)
        self.assertDictEqual(vc1.versionControl, vc.versionControl, the_file)

        saveVcContentInFile(vc, the_content, the_file)
        self.assertEqual(ut.safeFileExist(the_file), True, the_file)

        print(the_file + " : \n" + ut.to_json(getFileData(the_file)))

        content1 = ut.loadFileContent(the_file)
        vc1 = getVCfromContent(fileFormat(the_file), content1)
        self.assertDictEqual(vc1.versionControl, vc.versionControl, the_file)

        vc2 = VersionControl(getFileVc(the_file).asDict())
        self.assertDictEqual(vc2.versionControl, vc.versionControl, the_file)

        content3 = getFileContent(the_file)
        self.assertEqual(content3.strip(), the_content.strip())

        data = getFileData(the_file)
        print(str(data))
        self.assertEqual(data["Data"]["TT"], "TT")

        vc.setTag("TOTO")
        setVcInFile(vc, the_file)
        vc4 = getFileVc(the_file)
        self.assertDictEqual(vc4.versionControl, vc.versionControl, the_file)

        ut.safeFileRemove(the_file)

    def test_YamlFile(self):
        the_content = ' TT: TT \n'
        the_file    = "Test_VersionControl.yaml"
        the_type    = "yaml"
        the_data    = ut.loadDataContent(the_content)

        vc = VersionControl(comment="THE COMMENT YM", version="VERSIONYM", filename="FILEYM", fType=the_type, pID="IDYM", fileExt=ut.get_extension(the_file))
        self.assertEqual(vc.getVersion(), "VERSIONYM")
        self.assertEqual(vc.getID(), "IDYM")
        self.assertEqual(vc.getType(), the_type, the_file)
        self.assertEqual(vc.getExt(), ut.get_extension(the_file), the_file)

        saveVcContentInFile(vc, the_data, the_file)
        self.assertEqual(ut.safeFileExist(the_file), True, the_file)
        content1 = ut.loadFileContent(the_file)
        vc1 = getVCfromContent(fileFormat(the_file), content1)
        self.assertDictEqual(vc1.versionControl, vc.versionControl, the_file)

        saveVcContentInFile(vc, the_content, the_file)
        self.assertEqual(ut.safeFileExist(the_file), True, the_file)

        print(the_file + " : \n" + ut.to_yaml(getFileData(the_file)))

        content1 = ut.loadFileContent(the_file)
        vc1 = getVCfromContent(fileFormat(the_file), content1)
        self.assertDictEqual(vc1.versionControl, vc.versionControl, the_file)

        vc2 = VersionControl(getFileVc(the_file).asDict())
        self.assertDictEqual(vc2.versionControl, vc.versionControl, the_file)

        content3 = getFileContent(the_file)
        self.assertEqual(content3.strip(), the_content.strip())

        data = getFileData(the_file)
        self.assertEqual(data["Data"]["TT"], "TT")

        vc.setTag("TOTO")
        setVcInFile(vc, the_file)
        vc4 = getFileVc(the_file)
        self.assertDictEqual(vc4.versionControl, vc.versionControl, the_file)

        ut.safeFileRemove(the_file)


if __name__ == '__main__':
    unittest.main()
