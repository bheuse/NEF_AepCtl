pyreverse.exe -o dot -p FileStore DigitalContext Enricher RuleEngine DataServer Template KafkaClient KafkaServer  Template  Util Dependency ANM_NotificationEngine VersionControl
"C:\Program Files\Graphviz\bin\dot.exe" -Tjpg -oANM_RuleEngine.png  classes_ANM_RuleEngine.dot
"C:\Program Files\Google\Chrome\Application\chrome.exe" ANM_RuleEngine.png
pdoc --html FileStore DigitalContext Enricher RuleEngine DataServer Template KafkaClient KafkaServer  Template  Util Dependency ANM_NotificationEngine VersionControl
"C:\Program Files\Google\Chrome\Application\chrome.exe" html\index.html
