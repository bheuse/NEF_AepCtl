
@echo off

SET CHROMEPATH="C:\Program Files\Google\Chrome\Application"
SET PYTHONPATH=%HOMEPATH%\AppData\Local\Programs\Python\Python39\Scripts
SET PROJECTPATH=%HOMEPATH%\PycharmProjects\NEF_AepCtl

set FILE="C:%PROJECTPATH%\%1.py"

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
%PYTHONPATH%\pip.exe install     -r requirements.txt
%PYTHONPATH%\coverage.exe run    -m unittest %1.TestAll.test_all
REM %PYTHONPATH%\coverage.exe run    -m unittest %1.TestWso2Manager.test_all
%PYTHONPATH%\coverage.exe report -m
%PYTHONPATH%\coverage.exe html
%CHROMEPATH%\chrome.exe %PROJECTPATH%\htmlcov\%1_py.html"
REM cd "C:%PROJECTPATH%\scripts"

