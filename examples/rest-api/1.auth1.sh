#!/bin/bash

echo "Authentication"

CURL_OPTIONS="-k -v"
CURL_OPTIONS="-k "

echo ""
cat auth.json  | jq .
echo "" ; echo ""

curl $CURL_OPTIONS -X POST \
	-H "Authorization: Basic YWRtaW46YWRtaW4=" \
	-H "Content-Type: application/json" \
	-d @auth.json \
	https://localhost:9443/client-registration/v0.17/register \
	> auth1.response

echo ""
cat auth1.response  | jq .
echo "" ; echo ""

cat auth1.response | sed 's/\",\"clientName.*//' | sed 's/{\"clientId\"\:\"//'                      > client_id.txt
cat auth1.response | sed 's/\",\"isSaasApplication.*//' | sed 's/{\"clientId.*clientSecret\"\:\"//' > client_secret.txt


echo -n "client_id     : <" ; cat client_id.txt     ; echo ">"
echo -n "client_secret : <" ; cat client_secret.txt ; echo ">"

cat client_id.txt      > b64.txt
echo -n ":"           >> b64.txt
cat client_secret.txt >> b64.txt
echo -n "client_data   : <" ;  cat b64.txt ; echo ">"

base64  b64.txt > b64_client-token.txt
echo -n "client_b64    : " ;  cat b64_client-token.txt

