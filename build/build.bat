pyinstaller --noconfirm ../aepctl.py
copy dist\aepctl\aepctl.exe build
pyinstaller --noconfirm ../aepctlui.py
copy dist\aepctlui\aepctlui.exe build
