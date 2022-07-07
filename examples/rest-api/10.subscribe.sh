#!/bin/bash


CURL_OPTIONS="-k -v"
CURL_OPTIONS="-k "

echo "Subscribe App to API"

echo -n "access_token   : <" ; cat access_token.txt ; echo ">"
echo ""
echo -n "api-id   : <" ; cat api-id.txt ; echo ">"
echo -n "app-id   : <" ; cat app-id.txt ; echo ">"

echo "subscribe  : " ; cat subscribe.json | jq . ; echo ""
echo ""

cp subscribe.json.template subscribe.json
sed -i 's/API_ID/'$(cat api-id.txt)'/' subscribe.json
sed -i 's/APP_ID/'$(cat app-id.txt)'/' subscribe.json
curl $CURL_OPTIONS -X POST \
	-H "Authorization: Bearer "$(cat access_token.txt) \
	-H "Content-Type: application/json" \
	-d @subscribe.json \
	"https://localhost:9443/api/am/devportal/v2/subscriptions" \
	> subscribe.response

echo ""
cat subscribe.response | jq .
echo "" ; echo ""

cat subscribe.response | sed 's/\",\"applicationId.*//' | sed 's/{\"subscriptionId\"\:\"//'                      > subscription-id.txt

echo -n "subscription-id   : <" ;  cat subscription-id.txt ; echo ">"
