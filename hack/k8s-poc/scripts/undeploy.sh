#!/usr/bin/env bash

if [ $0 != "-bash" ] ; then
    pushd `dirname "$0"` > /dev/null 2>&1 
fi
KEYLIME_UNDEPLOY_DIR=$(pwd)
if [ $0 != "-bash" ] ; then
    popd > /dev/null 2>&1
fi

source $KEYLIME_UNDEPLOY_DIR/../util/common.sh

announce "Deleting Tenant Deployment..."
kubectl delete deployment.apps/keylime-tenant --namespace $KEYLIME_NAMESPACE

announce "Deleting Tenant Services..."
kubectl delete service/${KEYLIME_REGISTRAR_SERVICE_NAME}-http --namespace $KEYLIME_NAMESPACE
kubectl delete service/${KEYLIME_REGISTRAR_SERVICE_NAME} --namespace $KEYLIME_NAMESPACE

announce "Deleting Verifier StatefulSet..."
kubectl delete statefulset.apps/keylime-verifier --namespace $KEYLIME_NAMESPACE

announce "Deleting Verifier Services..."
kubectl delete service/${KEYLIME_VERIFIER_SERVICE_NAME} --namespace $KEYLIME_NAMESPACE
for ((i=0; i<$KEYLIME_VERIFIER_REPLICAS; i++))
do
    kubectl delete service/${KEYLIME_VERIFIER_SERVICE_NAME}-${i} --namespace $KEYLIME_NAMESPACE
done

announce "Deleting Registrar Deployment..."
kubectl delete deployment.apps/keylime-registrar --namespace $KEYLIME_NAMESPACE

announce "Deleting Keylime ConfigMap..."
kubectl delete configmap $KEYLIME_CFGMAP_NAME --namespace $KEYLIME_NAMESPACE

announce "Deleting Keylime Secrets..."
kubectl delete secret $KEYLIME_TLS_SECRETS_NAME --namespace $KEYLIME_NAMESPACE
kubectl delete secret $KEYLIME_EK_SECRETS_NAME --namespace $KEYLIME_NAMESPACE

if [[ $KEYLIME_DATABASE_UNDEPLOY -eq 1 ]]
then
    if [[ $KEYLIME_REGISTRAR_DATABASE_PROTOCOL != "sqlite" ]]
    then
        announce "Cleaning up Keylime Database..."

        cat <<EOF > ${KEYLIME_WORK_DIR}/registrar_dbcleanup.sh
#!/bin/bash
_mysql_conn="-NB --host=$KEYLIME_REGISTRAR_DATABASE_HOST --user=$KEYLIME_REGISTRAR_DATABASE_USER --password=$KEYLIME_REGISTRAR_DATABASE_PASSWORD"
mysql \${_mysql_conn} --execute "DROP DATABASE IF EXISTS \\\`$KEYLIME_REGISTRAR_DATABASE_NAME\\\`;"
EOF

        chmod +x ${KEYLIME_WORK_DIR}/registrar_dbcleanup.sh

        kubectl cp ${KEYLIME_WORK_DIR}/registrar_dbcleanup.sh mysqkeylimesetup-client:/tmp/ -c mysqkeylimesetup-client

        kubectl exec -it mysqkeylimesetup-client  -- bash -c "/tmp/registrar_dbcleanup.sh"
    fi

    if [[ $KEYLIME_VERIFIER_DATABASE_PROTOCOL != "sqlite" ]]
    then

        cat <<EOF > ${KEYLIME_WORK_DIR}/verifier_dbcleanup.sh
#!/bin/bash
_mysql_conn="-NB --host=$KEYLIME_VERIFIER_DATABASE_HOST --user=$KEYLIME_VERIFIER_DATABASE_USER --password=$KEYLIME_VERIFIER_DATABASE_PASSWORD"
mysql \${_mysql_conn} --execute "DROP DATABASE IF EXISTS \\\`$KEYLIME_VERIFIER_DATABASE_NAME\\\`;"
EOF

        chmod +x ${KEYLIME_WORK_DIR}/verifier_dbcleanup.sh

        kubectl cp ${KEYLIME_WORK_DIR}/verifier_dbcleanup.sh mysqkeylimesetup-client:/tmp/ -c mysqkeylimesetup-client

        kubectl exec -it mysqkeylimesetup-client  -- bash -c "/tmp/verifier_dbcleanup.sh"
    fi
fi 

echo $KEYLIME_REGISTRAR_DATABASE_URL | grep -q .svc.${KUBERNETES_DNS_DOMAIN}
if [[ $? -eq 0  ]]
then
    if [[ $KEYLIME_DATABASE_UNDEPLOY -eq 1 ]]
    then
        announce "Deleting Helm chart ${KEYLIME_DATABASE_DEPLOYMENT} ..."
        helm delete --wait --timeout=300s ${KEYLIME_DATABASE_DEPLOYMENT}
        announce "Deleteing PersistentVolumeClaims/*-${KEYLIME_DATABASE_DEPLOYMENT}-*"
        for _pvc in $(kubectl get persistentvolumeclaim --namespace $KEYLIME_DATABASE_NAMESPACE --no-headers | grep "\-${KEYLIME_DATABASE_DEPLOYMENT}\-" | awk '{ print $1 }')
        do
            kubectl delete persistentvolumeclaim/${_pvc} --namespace $KEYLIME_DATABASE_NAMESPACE 
        done
    fi
fi

if [[ ! -z ${KEYLIME_WORK_DIR} ]]
then
    rm -rf ${KEYLIME_WORK_DIR}
fi