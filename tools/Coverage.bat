
@echo off

SET CHROMEPATH="C:\Program Files\Google\Chrome\Application"
SET PYTHON=%HOMEPATH%\AppData\Local\Programs\Python\Python39\python.exe
SET PYTHONPATH=%HOMEPATH%\AppData\Local\Programs\Python\Python39\Scripts
SET PROJECTPATH=%HOMEPATH%\PycharmProjects\NEF_AepCtl

set MODULE=aepctl
set FUNCTION=TestDataStore.test_all_file
set FILE="C:%PROJECTPATH%\%MODULE%.py"


echo "================="
echo %FILE%
dir %FILE%
echo "================="

REM alias launchchrome="\"/mnt/c/Program Files/Google/Chrome/Application/chrome.exe\""

REM
REM mklink /D "%HOMEPATH%\Google\Drives\Projects" "C:\Users\bheuse\Google Drive (bh.projects06@gmail.com)\Projects"

REM %PYTHONPATH%\coverage.exe run    -m %1
REM echo %FILE%
REM %PYTHONPATH%\coverage.exe run    -m %FILE%
REM %PYTHONPATH%\coverage.exe report -m
REM %PYTHONPATH%\coverage.exe html
REM
REM %CHROMEPATH%\chrome.exe %PROJECTPATH%\anm_engine\htmlcov\%1_py.html"

REM dir %PYTHONPATH%\coverage.exe
REM echo %PYTHONPATH%\coverage.exe run    -m %FILE%

cd "C:%PROJECTPATH%"
%PYTHON%                         -m pip install --upgrade pip
%PYTHONPATH%\pip.exe install     -r requirements.txt

REM %PYTHONPATH%\coverage.exe run    -m unittest %MODULE%.TestAll.test_all
REM %PYTHONPATH%\coverage.exe run    -m unittest %MODULE%.TestWso2Manager.test_all

REM %PYTHONPATH%\coverage.exe run    -m unittest %MODULE%.%FUNCTION%
REM %PYTHONPATH%\coverage.exe report -m
REM %PYTHONPATH%\coverage.exe html
REM %CHROMEPATH%\chrome.exe %PROJECTPATH%\htmlcov\%MODULE%_py.html"

set MODULE=aepds
set FUNCTION=TestDataStore.test_all_file
set FILE="C:%PROJECTPATH%\%MODULE%.py"


REM %PYTHONPATH%\coverage.exe run    -m unittest %MODULE%.TestAll.test_all
%PYTHONPATH%\coverage.exe run    -m unittest %MODULE%.%FUNCTION%
REM %PYTHONPATH%\coverage.exe run    -m unittest %MODULE%.TestWso2Manager.test_all
%PYTHONPATH%\coverage.exe report -m
%PYTHONPATH%\coverage.exe html
%CHROMEPATH%\chrome.exe %PROJECTPATH%\htmlcov\%MODULE%_py.html"
REM cd "C:%PROJECTPATH%\scripts"


REM cd "C:%PROJECTPATH%\scripts"

