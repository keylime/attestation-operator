#!/usr/bin/env bash
if [ $0 != "-bash" ] ; then
    pushd `dirname "$0"` > /dev/null 2>&1 
fi
KEYLIME_BOOTSTRAP_DIR=$(pwd)
if [ $0 != "-bash" ] ; then
    popd > /dev/null 2>&1
fi

source $KEYLIME_BOOTSTRAP_DIR/../common.sh

if [[ -z $KEYLIME_PRE_GENERATED_CERTS_DIR ]]
then
    set -o errexit
    if [[ $KEYLIME_BUILD_WITH_DOCKER -eq 1 ]]
    then
        KEYLIME_CMD="docker run -it --rm -e KEYLIME_CA_PASSWORD=$KEYLIME_CA_PASSWORD -v $KEYLIME_WORK_DIR:/certs --entrypoint /bin/bash $KEYLIME_IMAGE_PREFIX/keylime_tenant -c \"keylime_ca -d /certs --command init\""
    else
        KEYLIME_CMD="keylime_ca -d ${KEYLIME_WORK_DIR} --command init"
    fi
    announce "Initializing certificates (\"$KEYLIME_CMD\")..."
    bash -c "$KEYLIME_CMD" > /dev/null 2>&1
    if [[ $KEYLIME_BUILD_WITH_DOCKER -eq 1 ]]
    then
        KEYLIME_CMD="docker run -it --rm -e KEYLIME_CA_PASSWORD=$KEYLIME_CA_PASSWORD -v $KEYLIME_WORK_DIR:/certs --entrypoint /bin/bash $KEYLIME_IMAGE_PREFIX/keylime_tenant -c \"keylime_ca -d /certs --command create --name server\""
    else
        KEYLIME_CMD="keylime_ca -d ${KEYLIME_WORK_DIR} --command create --name server"
    fi
    announce "Creating server certificates (\"$KEYLIME_CMD\")..."
    bash -c "$KEYLIME_CMD" > /dev/null 2>&1
    if [[ $KEYLIME_BUILD_WITH_DOCKER -eq 1 ]]
    then
        KEYLIME_CMD="docker run -it --rm -e KEYLIME_CA_PASSWORD=$KEYLIME_CA_PASSWORD -v $KEYLIME_WORK_DIR:/certs --entrypoint /bin/bash $KEYLIME_IMAGE_PREFIX/keylime_tenant -c \"keylime_ca -d /certs --command create --name client\""
    else   
    KEYLIME_CMD="keylime_ca -d ${KEYLIME_WORK_DIR} --command create --name client"
    fi
    announce "Creating client certificates (\"$KEYLIME_CMD\")..."
    bash -c "$KEYLIME_CMD" > /dev/null 2>&1
    set +o errexit
else
    set -o errexit
    ls $KEYLIME_PRE_GENERATED_CERTS_DIR/* > /dev/null 2>&1
    announce "Copying pre-generated certificates from $KEYLIME_PRE_GENERATED_CERTS_DIR to $KEYLIME_WORK_DIR ..."
    cp -f $KEYLIME_PRE_GENERATED_CERTS_DIR/*.{pem,der,crt,yml} $KEYLIME_WORK_DIR
    set +o errexit
fi

echo " "
ls -la $KEYLIME_WORK_DIR/*
echo " "

announce "Creating kubernetes generic secret $KEYLIME_TLS_SECRETS_NAME (namespace $KEYLIME_NAMESPACE) for TLS certificates and keys ..."
kubectl create secret generic $KEYLIME_TLS_SECRETS_NAME --namespace ${KEYLIME_NAMESPACE} --from-file=${KEYLIME_WORK_DIR}
kubectl get secret $KEYLIME_TLS_SECRETS_NAME --namespace ${KEYLIME_NAMESPACE}

if [[ ! -z $KEYLIME_EK_CERTS_DIR ]]
then
    echo " "
    ls -la $KEYLIME_EK_CERTS_DIR/*
    echo " "

    announce "Creating kubernetes generic secret $KEYLIME_EK_SECRETS_NAME (namespace $KEYLIME_NAMESPACE) for EK certificates ..."
    kubectl create secret generic $KEYLIME_EK_SECRETS_NAME --namespace ${KEYLIME_NAMESPACE} --from-file=${KEYLIME_EK_CERTS_DIR}
    kubectl get secret $KEYLIME_EK_SECRETS_NAME --namespace ${KEYLIME_NAMESPACE}
fi

if [[ ! -z ${KEYLIME_WORK_DIR} ]]
then
    rm -rf ${KEYLIME_WORK_DIR}
fi