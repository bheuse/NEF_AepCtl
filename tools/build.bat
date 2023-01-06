@echo off

mkdir ..\build
cd ..\build

pyinstaller --noconfirm --onefile ../aepctl.py
copy dist\aepctl.exe ..
pyinstaller --noconfirm --onefile ../aepctlui.py
copy dist\aepctlui.exe ..

