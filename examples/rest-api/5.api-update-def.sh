#!/bin/bash

echo "Load API Definition"

echo -n "access_token   : <" ; cat access_token.txt ; echo ">"
echo ""

echo "api-update  : " ; cat api-id.txt ; echo ""
echo ""

curl -k -X PUT \
	-H "Authorization: Bearer $(cat access_token.txt)" \
	-F file=@res.zip \
	"https://127.0.0.1:9443/api/am/publisher/v2/apis/$(cat api-id.txt)/swagger" \
	> api-update.response

echo ""
cat api-update.response | jq .
echo "" ; echo ""
