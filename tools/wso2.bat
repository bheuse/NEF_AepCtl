@echo off

SET CHROMEPATH="C:\Program Files\Google\Chrome\Application"
SET PYTHONPATH=%HOMEPATH%\AppData\Local\Programs\Python\Python39\Scripts
SET PROJECTPATH=%HOMEPATH%\PycharmProjects\NEF_AepCtl
SET WSO2PATH=%HOMEPATH%\PycharmProjects\wso2am-4.0.0

cd "C:%WSO2PATH%"\bin
%WSO2PATH%\bin\api-manager.bat
