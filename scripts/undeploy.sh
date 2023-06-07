#!/usr/bin/env bash

if [ $0 != "-bash" ] ; then
    pushd `dirname "$0"` > /dev/null 2>&1 
fi
KEYLIME_UNDEPLOY_DIR=$(pwd)
if [ $0 != "-bash" ] ; then
    popd > /dev/null 2>&1
fi

source $KEYLIME_UNDEPLOY_DIR/../util/common.sh

announce "Deleting Verifier Deployment..."
kubectl delete deployment.apps/keylime-verifier --namespace $KEYLIME_NAMESPACE

announce "Deleting Registrar Deployment..."
kubectl delete deployment.apps/keylime-registrar --namespace $KEYLIME_NAMESPACE

announce "Deleting Keylie ConfigMap..."
kubectl delete configmap keylime-config --namespace $KEYLIME_NAMESPACE

announce "Deleting Keylie Secrete..."
kubectl delete secret keylime-certs --namespace $KEYLIME_NAMESPACE

if [[ ! -z ${KEYLIME_WORK_DIR} ]]
then
    rm -rf ${KEYLIME_WORK_DIR}
fi