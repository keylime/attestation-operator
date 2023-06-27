#!/usr/bin/env bash

if [ $0 != "-bash" ] ; then
    pushd `dirname "$0"` > /dev/null 2>&1 
fi
KEYLIME_DEPLOY_DIR=$(pwd)
if [ $0 != "-bash" ] ; then
    popd > /dev/null 2>&1
fi

source $KEYLIME_DEPLOY_DIR/../util/common.sh

set -o errexit

#helm upgrade --install ingress-nginx ingress-nginx --repo https://kubernetes.github.io/ingress-nginx --namespace ingress-nginx --create-namespace --set "controller.extraArgs.enable-ssl-passthrough="

$KEYLIME_DEPLOY_DIR/../util/bootstrap/configmap.sh
$KEYLIME_DEPLOY_DIR/../util/bootstrap/secrets.sh
$KEYLIME_DEPLOY_DIR/../util/bootstrap/mysql.sh
$KEYLIME_DEPLOY_DIR/../util/services/registrar.sh
$KEYLIME_DEPLOY_DIR/../util/services/verifier.sh
$KEYLIME_DEPLOY_DIR/../util/operations/tenant.sh

if [[ ! -z ${KEYLIME_WORK_DIR} ]]
then
    rm -rf ${KEYLIME_WORK_DIR}
fi
