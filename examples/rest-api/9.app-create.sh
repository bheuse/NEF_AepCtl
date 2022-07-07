#!/bin/bash

echo "Create Application"

CURL_OPTIONS="-k -v"
CURL_OPTIONS="-k "

echo -n "access_token   : <" ; cat access_token.txt ; echo ">"
echo ""

echo "app-create  : " ; cat app-create | jq . ; echo ""
echo ""

curl $CURL_OPTIONS -X POST \
	-H "Authorization: Bearer $(cat access_token.txt)" \
	-H "Content-Type: application/json" \
	-d @app-create.json \
	"https://localhost:9443/api/am/devportal/v2/applications" \
	> app-create.response

echo ""
cat app-create.response  | jq .
echo "" ; echo ""

cat app-create.response | sed 's/\",\"name.*//' | sed 's/{\"applicationId\"\:\"//'                      > app-id.txt

echo ""
cat app-id.txt
echo "" ; echo ""
