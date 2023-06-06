#!/usr/bin/env bash
if [ $0 != "-bash" ] ; then
    pushd `dirname "$0"` > /dev/null 2>&1 
fi
KEYLIME_BOOTSTRAP_DIR=$(pwd)
if [ $0 != "-bash" ] ; then
    popd > /dev/null 2>&1
fi

source $KEYLIME_BOOTSTRAP_DIR/common.sh

set -o errexit
KEYLIME_CMD="keylime_ca -d ${KEYLIME_WORK_DIR} --command init"
announce "Initializing certificates (\"$KEYLIME_CMD\")..."
$KEYLIME_CMD > /dev/null 2>&1
KEYLIME_CMD="keylime_ca -d ${KEYLIME_WORK_DIR} --command create --name server"
announce "Creating server certificates (\"$KEYLIME_CMD\")..."
$KEYLIME_CMD > /dev/null 2>&1
KEYLIME_CMD="keylime_ca -d ${KEYLIME_WORK_DIR} --command create --name client"
announce "Creating client certificates (\"$KEYLIME_CMD\")..."
$KEYLIME_CMD > /dev/null 2>&1
set +o errexit

kubectl get secrets ${KEYLIME_SECRETS_NAME} --namespace ${KEYLIME_NAMESPACE} > /dev/null 2>&1
if [[ $? -eq 0 ]]
then
    announce "Deleting previous generic secret $KEYLIME_SECRETS_NAME (namespace $KEYLIME_NAMESPACE)"
    kubectl delete secrets ${KEYLIME_SECRETS_NAME} --namespace ${KEYLIME_NAMESPACE} > /dev/null 2>&1
fi

set -o errexit
announce "Creating kubernetes generic secret $KEYLIME_SECRETS_NAME (namespace $KEYLIME_NAMESPACE)..."
kubectl create secret generic $KEYLIME_SECRETS_NAME --namespace ${KEYLIME_NAMESPACE} --from-file=${KEYLIME_WORK_DIR}
set +o errexit

if [[ ! -z ${KEYLIME_WORK_DIR} ]]
then
    rm -rf ${KEYLIME_WORK_DIR}
fi