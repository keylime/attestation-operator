#!/usr/bin/env bash

function announce {
    # 1 - MESSAGE

	MESSAGE=$(echo "${1}" | tr '\n' ' ')
	MESSAGE=$(echo $MESSAGE | sed "s/\t\t*/ /g")

	echo "==> $(date) - ${0} - $MESSAGE"
}
export -f announce

function parse_kl_db_url {
    local _kl_db_full_url=$1
    local _component=$2

    if [[ ${_kl_db_full_url} == "auto" ]]
    then
        _protocol=mysql+pymysql
        export KEYLIME_${_component}_DATABASE_PROTOCOL=${_protocol}
        _password=${KEYLIME_DATABASE_PASSWORD}
        export KEYLIME_${_component}_DATABASE_PASSWORD=${_password}
        _user=${KEYLIME_DATABASE_USER}
        export KEYLIME_${_component}_DATABASE_USER=${_user}
        _port=3306
        export KEYLIME_${_component}_DATABASE_PORT=${_port}
        _host=${KEYLIME_DATABASE_DEPLOYMENT}-mysql.${KEYLIME_DATABASE_NAMESPACE}.svc.${KUBERNETES_DNS_DOMAIN}
        export KEYLIME_${_component}_DATABASE_HOST=${_host}
        _name=${KEYLIME_DATABASE_DEPLOYMENT}
        export KEYLIME_${_component}_DATABASE_NAME=${_name}
        export KEYLIME_${_component}_DATABASE_URL="${_protocol}://${_user}:${_password}@${_host}:${_port}/${_name}?charset=utf8"
        return
    fi

    _protocol="$(echo ${_kl_db_full_url} | grep '://' | sed -e's,^\(.*://\).*,\1,g')"

    export KEYLIME_${_component}_DATABASE_PROTOCOL=$(echo ${_protocol} | sed 's^://^^g')

    _kl_db_url=$(echo ${_kl_db_full_url} | sed -e s,${_protocol},,g)

    echo ${_kl_db_url} | grep -q '@'
    if [[ $? -eq 0 ]]
    then
        _userpass="$(echo ${_kl_db_url} | cut -d@ -f1)"
        echo ${_userpass} | grep -q ':'
        if [[ $? -eq 0 ]]
        then
            export KEYLIME_${_component}_DATABASE_PASSWORD=$(echo ${_userpass} | cut -d: -f2)
            export KEYLIME_${_component}_DATABASE_USER=$(echo ${_userpass} | cut -d: -f1)
        else
            export KEYLIME_${_component}_DATABASE_USER=$userpass
        fi
    fi

    echo ${_kl_db_url} | grep -q ':'
    if [[ $? -eq 0 ]]
    then
        if [[ ! -z ${_userpass} ]]
        then
            _hostport=$(echo ${_kl_db_url} | sed -e s,${_userpass}@,,g | cut -d/ -f1)
        else
            _hostport=$(echo ${_kl_db_url} | cut -d/ -f1)
        fi
        echo ${_hostport} | grep -q ':'
        if [[ $? -eq 0 ]]
        then
            export KEYLIME_${_component}_DATABASE_PORT=$(echo ${_hostport} | cut -d: -f2)
            export KEYLIME_${_component}_DATABASE_HOST=$(echo ${_hostport} | cut -d: -f1)
        else
            export KEYLIME_${_component}_DATABASE_HOST=${_hostport}
        fi
    fi

    _path="`echo $_kl_db_url | grep / | cut -d/ -f2-`"
    echo ${_path} | grep -q '?'
    if [[ $? -eq 0 ]]
    then
        export KEYLIME_${_component}_DATABASE_NAME=$(echo ${_path} | cut -d? -f1)
    else
        export KEYLIME_${_component}_DATABASE_NAME=${_path}
    fi
}
export -f parse_kl_db_url

function generate_service_entry {
    _svc_n=$1
    _svc_r=$2
    _svc_t=$3
    _svc_pi=$4
    _svc_pe=$5

    _svc_selector="role: ${_svc_n}"
    _svc_filename=${_svc_n}

    echo ${_svc_n} | grep -q - 
    if [[ $? -eq 0 ]]
    then
        _svc_selector="role: ${_svc_n}"
        _svc_filename=$(echo "${_svc_n}" | cut -d- -f1)
    fi

    echo ${_svc_n} | grep -q "\-[[:digit:]]"
    if [[ $? -eq 0 ]]
    then
        _svc_selector="statefulset.kubernetes.io/pod-name: keylime-${_svc_n}"
        _svc_filename=$(echo "${_svc_n}" | cut -d- -f1)
    fi
    cat <<EOF >> ${KEYLIME_WORK_DIR}/${_svc_filename}.yaml
---
apiVersion: v1
kind: Service
metadata:
  name: ${_svc_n}
  namespace: $KEYLIME_NAMESPACE
  labels:  
    app: keylime
    role: ${_svc_r}
spec:
  type: ${_svc_t}
  ports:
  - port: ${_svc_pi}
    targetPort: ${_svc_pi}
    nodePort: ${_svc_pe}
  selector:
    app: keylime
    ${_svc_selector}
EOF
}
export -f generate_service_entry

echo $0 | grep -q keylime_tenant
if [[ $? -ne 0 ]]
then
    KEYLIME_WORK_DIR=$(mktemp -d)
fi

KUBERNETES_DNS_DOMAIN=${KUBERNETES_DNS_DOMAIN:-"cluster.local"}
KEYLIME_NAMESPACE=${KEYLIME_NAMESPACE:-"keylime"}
KEYLIME_IMAGE_PREFIX=${KEYLIME_IMAGE_PREFIX:-"quay.io/keylime"}
KEYLIME_TLS_SECRETS_NAME=${KEYLIME_TLS_SECRETS_NAME:-"keylime-tls-certs"}
KEYLIME_EK_SECRETS_NAME=${KEYLIME_EK_SECRETS_NAME:-"keylime-ek-certs"}
KEYLIME_CFGMAP_NAME=${KEYLIME_CFGMAP_NAME:-"keylime-config"}
KEYLIME_BUILD_WITH_DOCKER=${KEYLIME_BUILD_WITH_DOCKER:-1}
KEYLIME_IMAGE_PULL_POLICY=${KEYLIME_IMAGE_PULL_POLICY:-"IfNotPresent"}

KEYLIME_REGISTRAR_POD_DEBUG=${KEYLIME_REGISTRAR_POD_DEBUG:-0}
KEYLIME_VERIFIER_POD_DEBUG=${KEYLIME_VERIFIER_POD_DEBUG:-0}

KEYLIME_REGISTRAR_REPLICAS=${KEYLIME_REGISTRAR_REPLICAS:-2}
KEYLIME_VERIFIER_REPLICAS=${KEYLIME_VERIFIER_REPLICAS:-2}

KEYLIME_REGISTRAR_SERVICE_NAME=${KEYLIME_REGISTRAR_SERVICE_NAME:-"registrar"}
KEYLIME_VERIFIER_SERVICE_NAME=${KEYLIME_VERIFIER_SERVICE_NAME:-"verifier"}

KEYLIME_DATABASE_NAMESPACE=${KEYLIME_DATABASE_NAMESPACE:-"default"}
KEYLIME_DATABASE_DEPLOYMENT=${KEYLIME_DATABASE_DEPLOYMENT:-"kldb"}
KEYLIME_DATABASE_PASSWORD=${KEYLIME_DATABASE_PASSWORD:-"temp4now"}
KEYLIME_DATABASE_USER=${KEYLIME_DATABASE_USER:-"root"}
KEYLIME_DATABASE_UNDEPLOY=${KEYLIME_DATABASE_UNDEPLOY:-0}

if [[ $KEYLIME_REGISTRAR_REPLICAS -gt 1 ]]
then
    KEYLIME_REGISTRAR_SERVICE_TYPE="LoadBalancer"
else
    KEYLIME_REGISTRAR_SERVICE_TYPE="NodePort"
fi

if [[ $KEYLIME_VERIFIER_REPLICAS -gt 1 ]]
then
    KEYLIME_VERIFIER_SERVICE_TYPE="LoadBalancer"
else
    KEYLIME_VERIFIER_SERVICE_TYPE="NodePort"
fi

KEYLIME_ENV_VARS_FILE=${KEYLIME_ENV_VARS_FILE:-"/etc/default/keylime"}
if [[ -f $KEYLIME_ENV_VARS_FILE ]]
then
    source $KEYLIME_ENV_VARS_FILE
fi

export KEYLIME_REGISTRAR_DATABASE_URL=${KEYLIME_REGISTRAR_DATABASE_URL:-"sqlite:////var/lib/keylime/cv_data.sqlite"}
export KEYLIME_VERIFIER_DATABASE_URL=${KEYLIME_VERIFIER_DATABASE_URL:-"sqlite:////var/lib/keylime/reg_data.sqlite"}

parse_kl_db_url $KEYLIME_REGISTRAR_DATABASE_URL REGISTRAR
parse_kl_db_url $KEYLIME_VERIFIER_DATABASE_URL VERIFIER

echo $0 | grep -q keylime_tenant
if [[ $? -ne 0 ]]
    then
    if [[ $KEYLIME_REGISTRAR_DATABASE_PROTOCOL == "sqlite" && $KEYLIME_REGISTRAR_REPLICAS -gt 1 ]]
    then
        announce "ERROR: scale-out deployments (KEYLIME_REGISTRAR_REPLICAS=$KEYLIME_REGISTRAR_REPLICAS) require a database."
        announce "set environment variable KEYLIME_REGISTRAR_DATABASE_URL to \"auto\" to deploy the DB via a helm chart automatically"
        exit 1
    fi

    if [[ $KEYLIME_VERIFIER_DATABASE_PROTOCOL == "sqlite" && $KEYLIME_VERIFIER_REPLICAS -gt 1 ]]
    then
        announce "ERROR: scale-out deployments (KEYLIME_VERIFIER_REPLICAS=$KEYLIME_VERIFIER_REPLICAS) require a database."
        announce "set environment variable KEYLIME_REGISTRAR_DATABASE_URL to \"auto\" to deploy the DB via a helm chart automatically"
        exit 1
    fi
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
export KEYLIME_VERIFIER_REPLICAS=${KEYLIME_VERIFIER_REPLICAS}
export KEYLIME_VERIFIER_SERVICE_NAME=${KEYLIME_VERIFIER_SERVICE_NAME}
export KEYLIME_VERIFIER_PORT=${KEYLIME_VERIFIER_PORT:-"8881"}
export KEYLIME_VERIFIER_TLS_DIR=${KEYLIME_VERIFIER_TLS_DIR:-"generate"}
export KEYLIME_VERIFIER_ENABLE_AGENT_MTLS=${KEYLIME_VERIFIER_ENABLE_AGENT_MTLS:-"False"}
#export KEYLIME_TENANT_REGISTRAR_IP=${KEYLIME_REGISTRAR_SERVICE_NAME}.${KEYLIME_NAMESPACE}.svc.${KUBERNETES_DNS_DOMAIN}
export KEYLIME_TENANT_REGISTRAR_IP=${KEYLIME_REGISTRAR_SERVICE_NAME}.${KEYLIME_NAMESPACE}
export KEYLIME_TENANT_REGISTRAR_PORT=${KEYLIME_REGISTRAR_TLS_PORT}
#export KEYLIME_TENANT_VERIFIER_IP=${KEYLIME_VERIFIER_SERVICE_NAME}.${KEYLIME_NAMESPACE}.svc.${KUBERNETES_DNS_DOMAIN}
export KEYLIME_TENANT_VERIFIER_IP=${KEYLIME_VERIFIER_SERVICE_NAME}.${KEYLIME_NAMESPACE}
export KEYLIME_TENANT_VERIFIER_PORT=${KEYLIME_VERIFIER_PORT}
export KEYLIME_TENANT_TPM_CERT_STORE=${KEYLIME_TENANT_TPM_CERT_STORE:-"/var/lib/keylime/tpm_cert_store/"}

kubectl get namespaces $KEYLIME_NAMESPACE > /dev/null 2>&1
if [[ $? -ne 0 ]]
then
    announce "Creating namespace ${KEYLIME_NAMESPACE} ..."
    kubectl create namespace ${KEYLIME_NAMESPACE}
fi
