#!/bin/bash

echo "Opening Connections ..."

/cygdrive/c/users/bheuse/PycharmProjects/NEF_AepCtl/kubectl.exe get pods -n pentest | grep wso2
/cygdrive/c/users/bheuse/PycharmProjects/NEF_AepCtl/kubectl.exe port-forward service/wso2am-single-node-am-service 9443:9443 -n pentest &
/cygdrive/c/users/bheuse/PycharmProjects/NEF_AepCtl/kubectl.exe port-forward service/wso2am-single-node-am-service 8243:8243 -n pentest &
/cygdrive/c/users/bheuse/PycharmProjects/NEF_AepCtl/kubectl.exe port-forward service/nef-services-catalog-service 30106:8080 -n pentest  &
/cygdrive/c/users/bheuse/PycharmProjects/NEF_AepCtl/kubectl.exe port-forward service/nef-application-user-profile-service 30107:8080 -n pentest  &


