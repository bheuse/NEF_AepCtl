pyreverse --colorized --class DataStoreInterface -o dot  ../aepctl.py
"C:\Program Files\Graphviz\bin\dot.exe" -Tjpg -oclasses.png  classes.dot
start classes.png
cd ..
pdoc --filter DataStore,Wso2,AepCtl,Factory,Store,Tmf --force --html aepctl.py
start html\aepctl.html
