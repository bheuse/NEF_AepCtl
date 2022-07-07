#!/bin/bash

echo "Deploy API"

CURL_OPTIONS="-k -v"
CURL_OPTIONS="-k "

echo -n "access_token   : <" ; cat access_token.txt ; echo ">"
echo ""

echo "generate-app-keys  : " ; cat generate-app-keys.json | jq . ; echo ""
echo ""

curl $CURL_OPTIONS POST \
	-H "Authorization: Bearer $(cat access_token.txt)" \
	-H "Content-Type: application/json" \
	-d @generate-app-keys.json \
	"https://localhost:9443/api/am/devportal/v2/applications/$(cat app-id.txt)/generate-keys" \
	> generate-app-keys.response

echo ""
cat generate-app-keys.response  | jq .
echo "" ; echo ""

cat generate-app-keys.response | sed 's/\",\"tokenScopes.*//' | sed 's/.*\"accessToken\"\:\"//' > app-key.txt

echo ""
cat app-key.txt
echo "" ; echo ""


