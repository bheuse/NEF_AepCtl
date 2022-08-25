#!/bin/bash

PIDS=`ps -ef |grep kubectl | awk '{ print $2 }'`
echo  Killing kubectl $PIDS
kill -9 $PIDS

WSO2_NAME_SPACE="pentest"
DATASTORE_NAME_SPACE="willibar"
DATASTORE_NAME_SPACE="pentest"

KUBE_CTL="/cygdrive/c/users/bheuse/PycharmProjects/NEF_AepCtl/tools/kubectl.exe"

echo "Opening Connections to $WSO2_NAME_SPACE for WSO2 ..."
$KUBE_CTL get pods -n $WSO2_NAME_SPACE | grep wso2
# $KUBE_CTL port-forward service/wso2am-single-node-am-service 9443:9443 -n $WSO2_NAME_SPACE &
# $KUBE_CTL port-forward service/wso2am-single-node-am-service 9243:8243 -n $WSO2_NAME_SPACE &

echo "Opening Connections to $DATASTORE_NAME_SPACE NameSpace for NEF_AepCtl ..."
$KUBE_CTL port-forward service/nef-services-catalog-service          32106:8080 -n $DATASTORE_NAME_SPACE  &
$KUBE_CTL port-forward service/nef-application-user-profile-service  32107:8080 -n $DATASTORE_NAME_SPACE  &

ps -ef | grep kubectl