#!/usr/bin/env bash

if [ $0 != "-bash" ] ; then
    pushd `dirname "$0"` > /dev/null 2>&1 
fi
KEYLIME_BOOTSTRAP_DIR=$(pwd)
if [ $0 != "-bash" ] ; then
    popd > /dev/null 2>&1
fi

source $KEYLIME_BOOTSTRAP_DIR/../common.sh

cat <<EOF > ${KEYLIME_WORK_DIR}/keylime-config.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: $KEYLIME_CFGMAP_NAME
  namespace: $KEYLIME_NAMESPACE
  labels:
    app: keylime
data:
EOF

for env_attr in $(env | grep ^KEYLIME_ | sort)
do
    cfg_file_type=$(echo $env_attr | cut -d '_' -f 2)
    cfg_attr_name=$(echo $env_attr | sed "s^KEYLIME_${cfg_file_type}_^^g" | cut -d '=' -f 1 | tr '[:upper:]' '[:lower:]')
    cfg_file_name=$(echo $cfg_file_type | tr '[:upper:]' '[:lower:]')".conf"
    env_attr_name=$(echo $env_attr | cut -d "=" -f 1)
    env_attr_value=$(echo $env_attr | sed "s/$env_attr_name=//g")
    if [[ -f $KEYLIME_LOCAL_CONFIG_FILE_DIR/$cfg_file_name ]]
    then
        grep -q ^${cfg_attr_name} $KEYLIME_LOCAL_CONFIG_FILE_DIR/$cfg_file_name
        if [[ $? -eq 0 ]]
        then
            echo "  "$env_attr_name": \""$env_attr_value"\"" >> ${KEYLIME_WORK_DIR}/keylime-config.yaml
        fi
    else 
        echo "  "$env_attr_name": \""$env_attr_value"\"" >> ${KEYLIME_WORK_DIR}/keylime-config.yaml
    fi
done

# Required for client-side load balancing
echo "  "KEYLIME_VERIFIER_SERVICE_NAME": \""$KEYLIME_VERIFIER_SERVICE_NAME"\"" >> ${KEYLIME_WORK_DIR}/keylime-config.yaml
echo "  "KEYLIME_VERIFIER_REPLICAS": \""$KEYLIME_VERIFIER_REPLICAS"\"" >> ${KEYLIME_WORK_DIR}/keylime-config.yaml
echo "  "KEYLIME_NAMESPACE": \""$KEYLIME_NAMESPACE"\"" >> ${KEYLIME_WORK_DIR}/keylime-config.yaml

echo " "
cat ${KEYLIME_WORK_DIR}/keylime-config.yaml
echo " "

set -o errexit
announce "Creating kubernetes configmap $KEYLIME_CFGMAP_NAME (namespace $KEYLIME_NAMESPACE) ..."
kubectl apply -f ${KEYLIME_WORK_DIR}/keylime-config.yaml
kubectl get configmap $KEYLIME_CFGMAP_NAME --namespace $KEYLIME_NAMESPACE
set +o errexit

if [[ ! -z ${KEYLIME_WORK_DIR} ]]
then
    rm -rf ${KEYLIME_WORK_DIR}
fi