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

By default, the `Makefile` looks for a yaml file on the path set by
the environment variable `HELM_CHART_CUSTOM_VALUES` (default
`values.yaml`)

### Registrars and verifiers: minimal deployment

This configuration deploys registrar, tenant and verifier pods. The
services are made available externally (i.e. the deployment can be
used to verify another cluster).

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

### Registrars and verifiers: using a mysql server

This configuration deploys a `verifier` and `registrar` sharing a
`MySQL` database (password will be automatically generated and
preserved across (`helm` updates)

The mysql server is deployed as part of the helm chart (that is, no
extra work is required).

```
global:
  database:
    mysql:
      enable: true
```

### Registars and verifiers: overriding site specifig configuration


This configuration demonstrates how to override Keylime configuration
parameters. Keylime allows configuration to be overridden by
environment variables.

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

### Keylime agent: deploy agents in privileged pods.

This configuration deploys Keylime agents in the cluster in a daemon
set. The pods running the keylime agent are privileged. We do not
recommend running this configuration in production mode, but may help
with debugging keylime agents.


```
tags:
  agent: true

global:
  service:
    agent:
      privileged: true
```

### Keylime agent: deploy agents in unprivileged pods

This configuration deploys Keylime agents in the cluster, but the pods
running the agent are unprivileged. The keylime agent needs access to
the TPM device and to parts of the `securityfs` file system. Both of
these are provided by the TPM device plugin, which is turned on
automatically with unprivileged agent pods.

In addition, the effective group ID of the keylime agent pod has to
match the group ID of the TPM device. Kubernetes does not allow
`runAsGroup` to take symbolic values.


TODO instructions for mounting the MBA and IMA logs in nonstandard places.

```
tags:
  agent: true

global:
  service:
    agent:
      privileged: false

keylime-agent:
  unprivsecurityContext:
    readOnlyRootFilesystem: true
    privileged: false
    capabilities:
      drop:
      - ALL
    runAsGroup: 109    <---- make this match the group ID of group <tss> on the hosts running the agent.
```



### Deploy with custom images (e.g. from a local registry)

This configuration is for those of us debugging custom (self-built)
keylime images. We imagine this to be the standard way to do Keylime
development.

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
