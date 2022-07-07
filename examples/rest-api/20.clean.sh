#!/bin/bash

APICTL='/cygdrive/c/users/bheuse/Google/Drives/Projects/PycharmProjects/ANM_Engine/wso2/apictl/apictl.exe -k -e production '

curl -k -v -X DELETE \
	-H "Authorization: Bearer "$(cat access_token.txt) \
	-H "Content-Type: application/json" \
	"https://localhost:9443/api/am/devportal/v2/subscriptions/$(cat subscription-id.txt)"

$APICTL delete app -n QosApp
$APICTL delete api -n 3gpp-as-session-with-qos-4 -v 1.1.4

curl -k -v -X DELETE \
	-H "Authorization: Bearer $(cat access_token.txt)" \
	"https://127.0.0.1:9443/api/am/admin/v2/throttling/policies/subscription/$(cat policy-id.txt)"

mkdir arch
mv *.response arch
mv *.txt      arch
