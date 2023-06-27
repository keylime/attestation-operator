if [ $0 != "-bash" ] ; then
    pushd `dirname "$0"` > /dev/null 2>&1 
fi
KEYLIME_BOOTSTRAP_DIR=$(pwd)
if [ $0 != "-bash" ] ; then
    popd > /dev/null 2>&1
fi

source $KEYLIME_BOOTSTRAP_DIR/../common.sh

echo $KEYLIME_REGISTRAR_DATABASE_URL | grep -q .svc.${KUBERNETES_DNS_DOMAIN}
if [[ $? -eq 0  ]]
then
    announce "Deploying Helm chart ${KEYLIME_DATABASE_DEPLOYMENT} ..."
    helm list -A --no-headers | grep "${KEYLIME_DATABASE_DEPLOYMENT}\s" > /dev/null 2>&1 
    if [[ $? -ne 0 ]]
    then
        KEYLIME_DATABASE_STORAGE_CLASS=$(kubectl get storageclass -A --no-headers | tail -1 | awk '{ print $1 }')
        if [[ -z $KEYLIME_DATABASE_STORAGE_CLASS ]]
        then
            announce "ERROR: No Storage Classes defined for this cluster, cannot deploy mysql helm chart"
            exit 1
        fi
        helm repo add bitnami https://charts.bitnami.com/bitnami
        helm install --timeout 300s --wait ${KEYLIME_DATABASE_DEPLOYMENT} bitnami/mysql --namespace $KEYLIME_DATABASE_NAMESPACE --create-namespace --set auth.rootPassword=$KEYLIME_REGISTRAR_DATABASE_PASSWORD --set global.storageClass=$KEYLIME_DATABASE_STORAGE_CLASS
        if [[ $? -ne 0 ]]
        then
            exit 1
        fi
    else
        announce "Helm chart ${KEYLIME_DATABASE_DEPLOYMENT} for already deployed"
    fi
fi

echo $KEYLIME_VERIFIER_DATABASE_URL | grep -q .svc.${KUBERNETES_DNS_DOMAIN}
if [[ $? -eq 0  ]]
then
    announce "Deploying Helm chart ${KEYLIME_DATABASE_DEPLOYMENT} ..."
    helm list -A --no-headers | grep "${KEYLIME_DATABASE_DEPLOYMENT}\s" > /dev/null 2>&1 
    if [[ $? -ne 0 ]]
    then
        KEYLIME_DATABASE_STORAGE_CLASS=$(kubectl get storageclass -A --no-headers | tail -1)
        if [[ -z $KEYLIME_DATABASE_STORAGE_CLASS ]]
        then
            announce "ERROR: No Storage Classes defined for this cluster, cannot deploy mysql helm chart"
            exit 1
        fi
        helm repo add bitnami https://charts.bitnami.com/bitnami
        helm install --timeout 300s --wait ${KEYLIME_DATABASE_DEPLOYMENT} bitnami/mysql --namespace $KEYLIME_DATABASE_NAMESPACE --create-namespace --set auth.rootPassword=$KEYLIME_VERIFIER_DATABASE_PASSWORD --set global.storageClass=$KEYLIME_DATABASE_STORAGE_CLASS
        if [[ $? -ne 0 ]]
        then
            exit 1
        fi
    else
        announce "Helm chart ${KEYLIME_DATABASE_DEPLOYMENT} for already deployed"
    fi
fi

if [[ $KEYLIME_REGISTRAR_DATABASE_PROTOCOL != "sqlite" ]]
then

    cat <<EOF > ${KEYLIME_WORK_DIR}/registrar_dbsetup.sh
#!/bin/bash
_mysql_conn="-NB --host=$KEYLIME_REGISTRAR_DATABASE_HOST --user=$KEYLIME_REGISTRAR_DATABASE_USER --password=$KEYLIME_REGISTRAR_DATABASE_PASSWORD"
mysql \${_mysql_conn} --execute "SHOW DATABASES;" | grep -q $KEYLIME_REGISTRAR_DATABASE_NAME
if [[ \$? -ne 0 ]]
then 
    mysql \${_mysql_conn} --execute "CREATE DATABASE \\\`$KEYLIME_REGISTRAR_DATABASE_NAME\\\`;"
    if [[ \$? -ne 0 ]]
    then
        exit \$?
    fi
    mysql \${_mysql_conn} --execute "SET GLOBAL max_connections = 8192;"
    if [[ \$? -ne 0 ]]
    then
        exit \$?
    fi
fi
EOF
    chmod +x ${KEYLIME_WORK_DIR}/registrar_dbsetup.sh
    cat <<EOF > ${KEYLIME_WORK_DIR}/verifier_dbsetup.sh
#!/bin/bash
_mysql_conn="-NB --host=$KEYLIME_VERIFIER_DATABASE_HOST --user=$KEYLIME_VERIFIER_DATABASE_USER --password=$KEYLIME_VERIFIER_DATABASE_PASSWORD"
mysql \${_mysql_conn} --execute "SHOW DATABASES;" | grep -q $KEYLIME_VERIFIER_DATABASE_NAME
if [[ \$? -ne 0 ]]
then 
    mysql \${_mysql_conn} --execute "CREATE DATABASE \\\`$KEYLIME_REGISTRAR_DATABASE_NAME\\\`;"
    if [[ \$? -ne 0 ]]
    then
        exit \$?
    fi
    mysql \${_mysql_conn} --execute "SET GLOBAL max_connections = 8192;"
    if [[ \$? -ne 0 ]]
    then
        exit \$?
    fi
fi
EOF
    chmod +x ${KEYLIME_WORK_DIR}/verifier_dbsetup.sh
    announce "Deploying a pod, \"mysqkeylimesetup-client\" in order to configure the database at ${KEYLIME_VERIFIER_DATABASE_HOST}:${KEYLIME_VERIFIER_DATABASE_PORT} used by Keylime\"..."
    kubectl get pod/mysqkeylimesetup-client --namespace $KEYLIME_DATABASE_NAMESPACE > /dev/null 2>&1 
    if [[ $? -ne 0 ]]
    then
        kubectl run mysqkeylimesetup-client --image docker.io/bitnami/mysql:8.0.33-debian-11-r17 --namespace $KEYLIME_DATABASE_NAMESPACE -- bash -c "while true; do sleep 30; done;"
    fi

    set -o errexit
    kubectl cp ${KEYLIME_WORK_DIR}/registrar_dbsetup.sh mysqkeylimesetup-client:/tmp/ -c mysqkeylimesetup-client
    kubectl cp ${KEYLIME_WORK_DIR}/verifier_dbsetup.sh mysqkeylimesetup-client:/tmp/ -c mysqkeylimesetup-client

    kubectl exec -it mysqkeylimesetup-client  -- bash -c "/tmp/registrar_dbsetup.sh"
    kubectl exec -it mysqkeylimesetup-client  -- bash -c "/tmp/verifier_dbsetup.sh"
fi

if [[ ! -z ${KEYLIME_WORK_DIR} ]]
then
    rm -rf ${KEYLIME_WORK_DIR}
fi