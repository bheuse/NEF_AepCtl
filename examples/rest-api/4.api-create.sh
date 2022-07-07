#!/bin/bash

CURL_OPTIONS="-k -v"
CURL_OPTIONS="-k "

echo "Create API"

echo -n "access_token   : <" ; cat access_token.txt ; echo ">"
echo ""

echo "api-create  : " ; cat api-create.json | jq . ; echo ""
echo ""

curl $CURL_OPTIONS -X POST \
	-H "Authorization: Bearer $(cat access_token.txt)" \
	-H "Content-Type: application/json" \
	-d @api-create.json \
	"https://127.0.0.1:9443/api/am/publisher/v2/apis"\
	> api-create.response

echo ""
cat api-create.response  | jq .
echo "" ; echo ""


cat api-create.response | sed 's/\",\"name.*//' | sed 's/{\"id\"\:\"//'        > api-id.txt

echo -n "api-id   : <" ;  cat api-id.txt ; echo ">"