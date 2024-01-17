#!/bin/bash

# #########################
# utility: clone AO main branch
# used only when this script is invoked outside AO CI
# #########################

function ao_clone() {
    local basedir=${1}
    local aodir=${2}
    local patchdir=${3}
    local realpatchdir=$(realpath ${patchdir})
    (cd ${basedir}
     if ! test -d ${basedir}/${aodir}
     then
         echo -n "Checking out AO ..."
         git clone https://github.com/keylime/attestation-operator ${aodir} > /tmp/ao-clone.log 2>&1
         if [[ $? != 0 ]]
         then
             echo "ERROR: failed to checkout AO. Attaching log."
             cat /tmp/ao-clone.log
             exit -1
         fi
         echo "  done"
         for f in $(find ${realpatchdir} -type f -name *.patch)
         do
             echo "Applying patches: ${f}"
             (cd ${aodir}; cat ${f} | patch -f -p1) > /dev/null 2>&1
         done
     fi
     return 0)
}

# #########################
# utility: build the AO helm chart
# #########################

function ao_build() {
    local aodir=${1}
    (cd ${aodir}
     echo -n "Building the helm chart ..."
     make helm-build > /tmp/helm-build.log 2>&1
     if [[ $? != 0 ]]
     then
         echo "\nERROR: helm build failed. Attaching log."
         cat /tmp/helm-build.log
         exit -1
     fi
     echo "done"
     return 0)
}


# #########################
# utility: deploy keylime with helm
# NOTE makes a link 
# #########################

function ao_deploy() {
    local aodir=${1}
    local values=${2}
    (cd ${aodir}
     echo -n "Deploying keylime with helm ... "
     make HELM_CHART_CUSTOM_VALUES=${values} \
          helm-keylime-deploy > /tmp/helm-deploy.log 2>&1
     if [[ $? != 0 ]]
     then
         echo "\nERROR: helm deploy failed. Attaching log."
         cat /tmp/helm-deploy.log
         exit -1
     fi
     echo "done"
     return 0)
}

# #########################
# step 6: wait until pods are running
# #########################

function ao_wait() {
    local aodir=${1}
    local podlist=${2:-"registrar tenant verifier"}
    local timeout=${3:-300}
    (cd ${aodir}
     local t0=$(date +%s)
     for comp in ${podlist}
     do
         echo -n "Waiting for ${comp} to be in run state: "
         while ! kubectl get pods -n keylime --no-headers | grep ${comp} | grep Run > /dev/null 2>&1
         do
             local t1=$(date +%s)
             if [[ ${t1} -gt $((t0+${timeout})) ]]
             then
                 echo "\nTIMED OUT."
                 exit -1
             fi
             echo -n "."
             sleep 5
         done
         echo "done"
     done
     echo "All components are running after $((t1-t0)) seconds."
     return 0)     
}

# #########################
# utility: clean up any previous deployments
# #########################

function ao_clean() {
    local aodir=${1}
    (cd ${aodir}
     echo -n "Removing any previous deployments of keylime ... "
     make helm-undeploy > /dev/null 2>&1
     echo "done"
     return 0)
}


# #########################
# simple, stupid keylime test
# #########################

function ao_simpletest() {
    local aodir=${1}
    (cd ${aodir}
     echo -n "Testing keylime function ... "
     make helm-keylime-test > /tmp/keylime-test.log 2>&1
     if [[ $? != 0 ]]
     then
         echo "\nERROR: test failed. Attaching log."
         cat /tmp/keylime-test.log
         exit -1
     fi
     echo "done"
     return 0)     
}


