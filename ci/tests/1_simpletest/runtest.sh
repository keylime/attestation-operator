#!/bin/bash

. ci/util/util_ao.sh

ao_build      . || exit -1
ao_clean      . || exit -1
ao_deploy     . ${PWD}/ci/tests/1_simpletest/values.yml || exit -1
ao_wait       . || exit -1
ao_simpletest . || exit -1
ao_clean      .
