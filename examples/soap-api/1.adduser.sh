#!/bin/bash


curl -k -X POST \
	-H "Authorization: Basic YWRtaW46YWRtaW4=" \
	-H "Content-Type: text/xml;charset=UTF-8" \
	-H "SOAPAction:urn:addUser" \
	-d @adduser.xml \
	--url https://localhost:9443/services/RemoteUserStoreManagerService.RemoteUserStoreManagerServiceHttpsSoap11Endpoint

