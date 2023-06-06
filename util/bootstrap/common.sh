#!/usr/bin/env bash

function announce {
    # 1 - MESSAGE

	MESSAGE=$(echo "${1}" | tr '\n' ' ')
	MESSAGE=$(echo $MESSAGE | sed "s/\t\t*/ /g")

	echo "==> $(date) - ${0} - $MESSAGE"
}
export -f announce

KEYLIME_NAMESPACE=${KEYLIME_NAMESPACE:-"keylime"}
KEYLIME_ENV_VARS_FILE=${KEYLIME_ENV_VARS_FILE:-"/etc/default/keylime"}
if [[ -f $KEYLIME_ENV_VARS_FILE ]]
then
    source $KEYLIME_ENV_VARS_FILE
fi

KEYLIME_SECRETS_NAME=${KEYLIME_SECRETS_NAME:-"keylime-certs"}
KEYLIME_CFGMAP_NAME=${KEYLIME_CFGMAP_NAME:-"keylime-config"}

KEYLIME_ACTUAL_CERTS_DIR=$(python3 -c "from keylime import config, web_util; dir=web_util.get_tls_dir(\"verifier\"); print(dir)" 2>/dev/null | grep -v keylime.config)
if [[ -z ${KEYLIME_ACTUAL_CERTS_DIR} ]]
then
    announce "ERROR, unable to determine actual keylime certificates dir"
    exit 1
fi

kubectl get namespaces $KEYLIME_NAMESPACE > /dev/null 2>&1
if [[ $? -ne 0 ]]
then
    announce "Creating namespace ${KEYLIME_NAMESPACE} ..."
    kubectl create namespace ${KEYLIME_NAMESPACE}
fi
 
KEYLIME_WORK_DIR=$(mktemp -d)