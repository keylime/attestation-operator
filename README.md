# attestation-operator

[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202-blue)](https://www.apache.org/licenses/LICENSE-2.0)

Keylime easily deployable on Kubernetes/Openshift.

**NOTE:** This project is a work in progress.

## Pre-requisites:
* Running `Kubernetes` cluster (evidently)
* If one wishes to deploy `agents` (which are deployed by default) the following additional requirements should be in place:
    * All workers nodes should have TPM devices (e.g., `ls /dev/tpm*` should exit with 0)
    * For **unprivileged** pods, K8s version `1.26` or later is required and [k8s-tpm-device-plugin](https://github.com/githedgehog/k8s-tpm-device-plugin) shall be installed beforehand. 
    * IMPORTANT: the default mode of operation for this helm chart is to deploy containers with a DameonSet with **privileged** pods.

## Initial deployment
a) `git clone https://github.com/keylime/attestation-operator.git; cd attestation-operator`
b) `make help`
```
Usage:
  make <target>

General
  help             Display this help.

Build
  helm             Builds all helm charts
  helm-clean       Cleans all packaged helm charts
  helm-build       Builds the keylime helm chart
  helm-keylime-clean  Cleans the packaged keylime helm chart
  helm-keylime-undeploy  Undeploy the keylime helm chart
  helm-keylime-deploy  Deploy the keylime helm chart
  helm-keylime-update  Update the deployed keylime helm chart
  helm-keylime-debug  Attempt to debug the keylime helm chart, without deploying
  helm-keylime-push  Builds AND pushes the keylime helm chart
```
c) `make helm-build`

d) `make helm-deploy` will deploy an initial barebones (but functional) deployment with 1 `registrar` (a `Deployment` with a single pod), 1 `verifier` (a `Deployment` with. a single pod), each backed by their own private `sqlite` (in-pod) database and `agents` on every node (as a `DaemonSet`)

e) `make helm-undeploy` will remove the whole deployment

## Customizing the deployment.
By default, the `Makefile` looks for an yaml file on the path set by the environment variable `HELM_CHART_CUSTOM_VALUES` (default `values.yaml`)

Below we have a couple of examples for some customizations

1 - Do not deploy the `agents` as part of the cluster, and make the services available externally

```
tags:
  init: true
  registrar: true
  verifier: true
  agent: false
  tenant: true

global:
  service:
    registrar:
      type: NodePort
    verifier:
      type: NodePort
```

2 - Deploy with both `verifier` and `registrar` sharing a `MySQL` database (password will be automatically generated and preserved across (`helm` updates)
```
global:
  database:
    mysql:
      enable: true
```

3 - Add additional site-specific configuration parameters
```
global:
  configmap:
    configParams:
      KEYLIME_AGENT_ENABLE_AGENT_MTLS: 'False'
      KEYLIME_AGENT_ENABLE_INSECURE_PAYLOAD: 'True'
      KEYLIME_AGENT_RUN_AS: root:root
      KEYLIME_AGENT_TPM_ENCRYPTION_ALG: rsa
      KEYLIME_AGENT_TPM_HASH_ALG: sha256
      KEYLIME_AGENT_TPM_OWNERPASSWORD: temp4now
      KEYLIME_AGENT_TPM_SIGNING_ALG: rsassa
      KEYLIME_CA_CERT_CA_NAME: feykimeluckers
      KEYLIME_CA_CERT_CRL_DIST: http://100.64.255.11:3808/crl
      KEYLIME_CA_CERT_LOCALITY: YKT
      KEYLIME_CA_CERT_ORGANIZATION: IBM
      KEYLIME_CA_CERT_ORG_UNIT: k5l
      KEYLIME_CA_CERT_STATE: NY
      KEYLIME_CA_PASSWORD: temp4now
      KEYLIME_REGISTRAR_AUTO_MIGRATE_DB: 'True'
      KEYLIME_REGISTRAR_DATABASE_POOL_SZ_OVFL: 40,80
      KEYLIME_TENANT_ENABLE_AGENT_MTLS: 'False'
      KEYLIME_TENANT_MAX_PAYLOAD_SIZE: '1048576'
      KEYLIME_TENANT_REQUIRE_EK_CERT: 'True'
      KEYLIME_VERIFIER_AUTO_MIGRATE_DB: 'True'
      KEYLIME_VERIFIER_DATABASE_POOL_SZ_OVFL: 40,80
      KEYLIME_VERIFIER_ENABLE_AGENT_MTLS: 'False'
      KEYLIME_VERIFIER_QUOTE_INTERVAL: '5'
```

4 - Deploy agents with unprivileged pods
```
global:
  service:
    agent:
      privileged: false
```

5 - Deploy with custom images (e.g. from a local registry)
```
global:
  service:
    agent:
      initImage:
        repository: localhost/custom-agent-initImage
        tag: latest
      image:
        repository: localhost/custom-agent-image
        tag: latest
    registrar:
      image:
        repository: localhost/custom-registrar-image
        tag: latest
    verifier:
      image:
        repository: localhost/custom-verifier-image
        tag: latest
    tenant:
      image:
        repository: localhost/custom-tenant-image
        tag: latest
```
