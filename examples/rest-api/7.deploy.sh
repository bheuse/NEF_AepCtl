#!/bin/bash

echo "Deploy API"

CURL_OPTIONS="-k -v"
CURL_OPTIONS="-k "

echo -n "access_token   : <" ; cat access_token.txt ; echo ">"
echo ""

echo "rev-deploy  : " ; cat deploy.json | jq . ; echo ""
echo ""

curl $CURL_OPTIONS -X POST \
	-H "Authorization: Bearer $(cat access_token.txt)"  \
	-H "Content-Type:application/json" \
	-d @deploy.json \
	"https://127.0.0.1:9443/api/am/publisher/v2/apis/$(cat api-id.txt)/deploy-revision?revisionId=$(cat rev-id.txt)" \
	> deploy.response

echo ""
cat deploy.response | jq .
echo "" ; echo ""




