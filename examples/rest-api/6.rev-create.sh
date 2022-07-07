#!/bin/bash

echo "Create Revision"

CURL_OPTIONS="-k -v"
CURL_OPTIONS="-k "

echo "Revision API "$(cat api-id.txt)

echo -n "access_token   : <" ; cat access_token.txt ; echo ">"
echo ""

echo "rev-create  : " ; cat rev-create.json | jq . ; echo ""
echo ""

curl $CURL_OPTIONS -X POST \
	-H "Authorization: Bearer $(cat access_token.txt)" \
	-H "Content-Type: application/json" \
	-d @rev-create.json \
	"https://127.0.0.1:9443/api/am/publisher/v2/apis/$(cat api-id.txt)/revisions" \
	> rev-create.response

echo ""
cat rev-create.response | jq .
echo "" ; echo ""

cat rev-create.response | sed 's/\",\"description.*//' | sed 's/.*\"id\"\:\"//' > rev-id.txt

echo -n "rev-id   : <" ;  cat rev-id.txt ; echo ">"
