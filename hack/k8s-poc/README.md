# Kubernetes Proof of Concept

This is the initial work for a proof of concept for running keylime on Kubernetes.

**Requirements:**

- keylime has to be installed on the local machine
- docker needs to be running and accessible for the current user of the local machine

`scripts/deploy.sh` will deploy the keylime registrar, verifier and tenant in a Kubernetes cluster.
It will template a ConfigMap and Secret for the necessary operation on the fly.

`scripts/undeploy.sh` will uninstall all components.

The `keylime_tenant` script in the `admin` folder will interact with the tenant Kubernetes pod in a transparent way to run tenant commands.
