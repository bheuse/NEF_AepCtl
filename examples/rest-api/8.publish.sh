#!/bin/bash

echo "Publish API "$(cat api-id.txt)

CURL_OPTIONS="-k -v"
CURL_OPTIONS="-k "

echo -n "access_token   : <" ; cat access_token.txt ; echo ">"
echo ""

curl $CURL_OPTIONS -X POST \
	-H "Authorization: Bearer $(cat access_token.txt)" \
	"https://127.0.0.1:9443/api/am/publisher/v2/apis/change-lifecycle?apiId=$(cat api-id.txt)&action=Publish" \
	> publish.response

echo ""
cat publish.response | jq .
echo "" ; echo ""