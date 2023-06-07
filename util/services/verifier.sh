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
s^REPLACE_KEYLIME_SECRETS_NAME^$KEYLIME_SECRETS_NAME^g
s^REPLACE_KEYLIME_VERIFIER_PORT_EXTERNAL^$((KEYLIME_VERIFIER_PORT+KEYLIME_SERVICE_PORT_OFFSET))^g
s^REPLACE_KEYLIME_VERIFIER_PORT^$KEYLIME_VERIFIER_PORT^g
EOF

cat $KEYLIME_SERVICE_DIR/../../templates/verifier.yaml.in | sed -f ${KEYLIME_WORK_DIR}/sed-commands > ${KEYLIME_WORK_DIR}/verifier.yaml

echo " "
cat ${KEYLIME_WORK_DIR}/verifier.yaml
echo " "

kubectl apply -f ${KEYLIME_WORK_DIR}/verifier.yaml

if [[ ! -z ${KEYLIME_WORK_DIR} ]]
then
    rm -rf ${KEYLIME_WORK_DIR}
fi