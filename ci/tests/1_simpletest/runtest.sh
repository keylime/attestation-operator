#!/bin/bash

bindir=$(dirname $(realpath $0))
cd ${bindir}/../../..

. ci/util/util_ao.sh

ao_build      . || exit -1
ao_clean      . || exit -1
ao_deploy     . ${bindir}/values.yml || exit -1
ao_wait       . || exit -1
ao_simpletest . || exit -1
ao_clean      .
