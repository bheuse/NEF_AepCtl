#!/bin/bash

CURL_OPTIONS="-k -v"
CURL_OPTIONS="-k "

echo "Create Policy"

echo -n "access_token   : <" ; cat access_token.txt ; echo ">"
echo ""

echo "policy-create  : " ; cat policy-create.json  | jq . ; echo ""
echo ""

curl $CURL_OPTIONS -X POST \
	-H "Authorization: Bearer $(cat access_token.txt)" \
	-H "Content-Type: application/json" \
	-d @policy-create.json \
	"https://127.0.0.1:9443/api/am/admin/v2/throttling/policies/subscription" \
	> policy-create.response

echo ""
cat policy-create.response  | jq .
echo "" ; echo ""

cat policy-create.response | sed 's/\",\"policyName.*//' | sed 's/{\"policyId\"\:\"//'        > policy-id.txt

echo -n "policy-id   : <" ;  cat policy-id.txt ; echo ">"
