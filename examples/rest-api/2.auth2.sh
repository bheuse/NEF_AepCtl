#!/bin/bash

CURL_OPTIONS="-k -v"
CURL_OPTIONS="-k "

echo "Authorization Request"

echo -n "client_b64    : " ;  cat b64_client-token.txt

curl https://localhost:9443/oauth2/token $CURL_OPTIONS  \
	-H "Authorization: Basic $(cat b64_client-token.txt)" \
	-d "grant_type=password&username=admin&password=admin&scope=apim:api_view apim:api_create apim:api_publish apim:subscribe apim:app_manage apim:api_key apim:admin apim:tier_view apim:tier_manage" \
	> auth2.response

echo ""
cat auth2.response  | jq .
echo "" ; echo ""

cat auth2.response | sed 's/\",\"refresh_token.*//' | sed 's/{\"access_token\"\:\"//'        > access_token.txt
cat auth2.response | sed 's/\",\"scope.*//' | sed 's/{\"access_token.*refresh_token\"\:\"//' > refresh_token.txt

echo -n "access_token  : <" ; cat access_token.txt  ; echo ">"
echo -n "refresh_token : <" ; cat refresh_token.txt ; echo ">"