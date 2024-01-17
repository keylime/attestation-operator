#!/usr/bin/env bash
if [ $0 != "-bash" ] ; then
    pushd `dirname "$0"` > /dev/null 2>&1 
fi
KEYLIME_SERVICE_DIR=$(pwd)
if [ $0 != "-bash" ] ; then
    popd > /dev/null 2>&1
fi

source $KEYLIME_SERVICE_DIR/../common.sh

cat <<EOF > ${KEYLIME_WORK_DIR}/sed-commands
s^REPLACE_KEYLIME_NAMESPACE^$KEYLIME_NAMESPACE^g
s^REPLACE_KEYLIME_IMAGE_PREFIX^$KEYLIME_IMAGE_PREFIX^g
s^REPLACE_KEYLIME_ACTUAL_CERTS_DIR^$KEYLIME_ACTUAL_CERTS_DIR^g
s^REPLACE_KEYLIME_CFGMAP_NAME^$KEYLIME_CFGMAP_NAME^g
s^REPLACE_KEYLIME_TLS_SECRETS_NAME^$KEYLIME_TLS_SECRETS_NAME^g
s^REPLACE_KEYLIME_EK_SECRETS_NAME^$KEYLIME_EK_SECRETS_NAME^g
s^REPLACE_KEYLIME_TENANT_TPM_CERT_STORE^$KEYLIME_TENANT_TPM_CERT_STORE^g
s^REPLACE_KEYLIME_IMAGE_PULL_POLICY^$KEYLIME_IMAGE_PULL_POLICY^g
s^REPLACE_KEYLIME_VERIFIER_PORT^$((KEYLIME_VERIFIER_PORT+KEYLIME_SERVICE_PORT_OFFSET))^g
s^REPLACE_KEYLIME_REGISTRAR_PORT^$((KEYLIME_REGISTRAR_PORT+KEYLIME_SERVICE_PORT_OFFSET))^g
s^REPLACE_KEYLIME_REGISTRAR_TLS_PORT^$((KEYLIME_REGISTRAR_TLS_PORT+KEYLIME_SERVICE_PORT_OFFSET))^g
EOF

if [[ ! -z $KEYLIME_EK_CERTS_DIR ]]
then
    echo "s^#EKCERTS^^g" >> ${KEYLIME_WORK_DIR}/sed-commands
fi

cat $KEYLIME_SERVICE_DIR/../../templates/tenant.yaml.in | sed -f ${KEYLIME_WORK_DIR}/sed-commands > ${KEYLIME_WORK_DIR}/tenant.yaml

echo " "
cat ${KEYLIME_WORK_DIR}/tenant.yaml
echo " "

kubectl apply -f ${KEYLIME_WORK_DIR}/tenant.yaml

kubectl wait --for=condition=available --timeout=600s deployment.apps/keylime-tenant --namespace ${KEYLIME_NAMESPACE}

sleep 5

KEYLIME_TENANT_POD=$(kubectl get pods --namespace ${KEYLIME_NAMESPACE} | grep tenant | awk '{ print $1 }')

cat <<EOF > ${KEYLIME_WORK_DIR}/kt.sh

#!/usr/bin/env bash

function verifier_from_agent_uuid {
    _number_of_verifiers=\$1
    _agent_uuid=\$2

    _agent_hash=\$(echo \$((0x\$(sha1sum <<<"\${_agent_uuid}")0)))

    _verifier_nr=\$((_agent_hash%_number_of_verifiers))

    echo \$KEYLIME_VERIFIER_SERVICE_NAME-\${_verifier_nr}
}

KEYLIME_RECEIVED_COMMAND="\$*"

while [[ \$# -gt 0 ]]
do
    key="\$1"

    case \$key in
        -u=*|--uuid=*)
        export KEYLIME_TENANT_AGENT_UUID=$(echo \$key | cut -d '=' -f 2)
        ;;
        -u|--uuid)
        export KEYLIME_TENANT_AGENT_UUID="\$2"
        shift
        ;;
        -c=*|--command=*)
        export KEYLIME_TENANT_COMMAND=$(echo \$key | cut -d '=' -f 2)
        ;;
        -c|--command)
        export KEYLIME_TENANT_COMMAND="\$2"
        shift
        ;;        
        -h|--help)
        keylime_tenant -h
        exit 0
        ;;
        *)
        # unknown option
        ;;
        esac
        shift
done

echo \$KEYLIME_TENANT_COMMAND | grep -q all
if [[ \$? -eq 0 ]]
then
    for _uuid in \$(keylime_tenant -c reglist | grep retrieved | sed 's/.*retrieved //' | jq -r .results.uuids[]);
    do
        export KEYLIME_TENANT_VERIFIER_IP=\$(verifier_from_agent_uuid \$KEYLIME_VERIFIER_REPLICAS \${_uuid}).\${KEYLIME_NAMESPACE}
        keylime_tenant -c \$(echo \$KEYLIME_TENANT_COMMAND | sed 's/all//g') -u \${_uuid} -f /tmp/empty
    done
else
    if [[ ! -z \$KEYLIME_TENANT_AGENT_UUID ]]
    then
         export KEYLIME_TENANT_VERIFIER_IP=\$(verifier_from_agent_uuid \$KEYLIME_VERIFIER_REPLICAS \$KEYLIME_TENANT_AGENT_UUID).\$KEYLIME_NAMESPACE
    fi
    keylime_tenant \$KEYLIME_RECEIVED_COMMAND
fi
EOF

chmod +x ${KEYLIME_WORK_DIR}/kt.sh

kubectl cp ${KEYLIME_WORK_DIR}/kt.sh $KEYLIME_TENANT_POD:/usr/local/bin/kt --namespace ${KEYLIME_NAMESPACE} -c tenant

if [[ ! -z $KEYLIME_TENANT_EK_CHECK_SCRIPT ]]
then
    cat <<EOF > ${KEYLIME_WORK_DIR}/ekcheck.sh
#!/bin/bash
exit 0
EOF

    chmod +x ${KEYLIME_WORK_DIR}/ekcheck.sh

    kubectl cp ${KEYLIME_WORK_DIR}/ekcheck.sh $KEYLIME_TENANT_POD:$KEYLIME_TENANT_EK_CHECK_SCRIPT --namespace ${KEYLIME_NAMESPACE} -c tenant
fi

kubectl exec -it $KEYLIME_TENANT_POD --namespace ${KEYLIME_NAMESPACE} -- bash -c "dnf -y install jq; touch /tmp/empty"  > /dev/null 2>&1 

if [[ ! -z ${KEYLIME_WORK_DIR} ]]
then
    rm -rf ${KEYLIME_WORK_DIR}
fi
