#!/usr/bin/env bash

function announce {
    # 1 - MESSAGE

	MESSAGE=$(echo "${1}" | tr '\n' ' ')
	MESSAGE=$(echo $MESSAGE | sed "s/\t\t*/ /g")

	echo "==> $(date) - ${0} - $MESSAGE"
}
export -f announce

KEYLIME_NAMESPACE=${KEYLIME_NAMESPACE:-"keylime"}
KEYLIME_IMAGE_PREFIX=${KEYLIME_IMAGE_PREFIX:-"quay.io/keylime"}
KEYLIME_SECRETS_NAME=${KEYLIME_SECRETS_NAME:-"keylime-certs"}
KEYLIME_CFGMAP_NAME=${KEYLIME_CFGMAP_NAME:-"keylime-config"}
KEYLIME_BUILD_WITH_DOCKER=${KEYLIME_BUILD_WITH_DOCKER:-1}

KEYLIME_ENV_VARS_FILE=${KEYLIME_ENV_VARS_FILE:-"/etc/default/keylime"}
if [[ -f $KEYLIME_ENV_VARS_FILE ]]
then
    source $KEYLIME_ENV_VARS_FILE
fi

KEYLIME_SERVICE_PORT_OFFSET=${KEYLIME_SERVICE_PORT_OFFSET:-"21200"}
# Force the following keylime configuration file attributes, suitable for a Kubernetes deployment
export KEYLIME_ACTUAL_CERTS_DIR=${KEYLIME_ACTUAL_CERTS_DIR:-"/var/lib/keylime/cv_ca/"}
export KEYLIME_CA_PASSWORD=${KEYLIME_CA_PASSWORD:-$(openssl rand -base64 32)}
export KEYLIME_REGISTRAR_IP=0.0.0.0
export KEYLIME_REGISTRAR_PORT=${KEYLIME_REGISTRAR_PORT:-"8890"}
export KEYLIME_REGISTRAR_TLS_PORT=${KEYLIME_REGISTRAR_TLS_PORT:-"8891"}
export KEYLIME_REGISTRAR_TLS_DIR=${KEYLIME_REGISTRAR_TLS_DIR:-"default"}
export KEYLIME_VERIFIER_IP=0.0.0.0
export KEYLIME_VERIFIER_PORT=${KEYLIME_VERIFIER_PORT:-"8881"}
export KEYLIME_VERIFIER_TLS_DIR=${KEYLIME_VERIFIER_TLS_DIR:-"generate"}
export KEYLIME_VERIFIER_ENABLE_AGENT_MTLS=${KEYLIME_VERIFIER_ENABLE_AGENT_MTLS:-"False"}

kubectl get namespaces $KEYLIME_NAMESPACE > /dev/null 2>&1
if [[ $? -ne 0 ]]
then
    announce "Creating namespace ${KEYLIME_NAMESPACE} ..."
    kubectl create namespace ${KEYLIME_NAMESPACE}
fi
 
KEYLIME_WORK_DIR=$(mktemp -d)