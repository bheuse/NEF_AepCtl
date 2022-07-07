#!/bin/bash

echo "Publish API "$(cat api-id.txt)

CURL_OPTIONS="-k -v"
CURL_OPTIONS="-k "

echo -n "app-key   : <" ; cat app-key.txt ; echo ">"
echo ""

curl $CURL_OPTIONS -X GET \
	"https://localhost:8243/qos/1.1.4/1/subscriptions" \
	-H  "accept: application/json" \
	-H  "Authorization: Bearer $(cat app-key.txt)"\
	> test.response

echo ""
cat test.response | jq .
echo "" ; echo ""


