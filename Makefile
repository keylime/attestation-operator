# Copyright 2023 The Keylime Authors
# SPDX-License-Identifier: Apache-2.0
#
SHELL := bash
.SHELLFLAGS := -e -c
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --no-builtin-rules
MKFILE_DIR := $(shell echo $(dir $(abspath $(lastword $(MAKEFILE_LIST)))) | sed 'sA/$$AA')

BUILD_DIR := $(MKFILE_DIR)/build
BUILD_ARTIFACTS_DIR := $(BUILD_DIR)/artifacts
HACK_DIR := $(MKFILE_DIR)/hack

# NOTE: this will change once we add the operator
VERSION ?= latest

# helm chart version must be semver 2 compliant
HELM_CHART_KEYLIME_VERSION ?= 0.1.0
HELM_CHART_RELEASE_NAME ?= hhkl
HELM_CHART_NAMESPACE ?= keylime
HELM_CHART_CUSTOM_VALUES ?= values.yaml
HELM_CHART_DEBUG_FILE ?= /tmp/keylime.helm.debug
HELM_CHART_KEYLIME_DIR := $(BUILD_DIR)/helm/keylime
HELM_CHART_KEYLIME_FILES := $(shell find $(HELM_CHART_KEYLIME_DIR) -type f)
HELM_CHART_REPO ?= ghcr.io/keylime/helm-charts

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk commands is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

all: helm

##@ Build

helm: helm-keylime ## Builds all helm charts

.PHONY: helm-clean
helm-clean: helm-keylime-clean ## Cleans all packaged helm charts

.PHONY: helm-undeploy
helm-undeploy: helm-keylime-undeploy

.PHONY: helm-deploy
helm-deploy: helm-keylime-deploy

.PHONY: helm-update
helm-deploy: helm-keylime-update

.PHONY: helm-debug
helm-debug: helm-keylime-debug

helm-build: $(BUILD_ARTIFACTS_DIR)/keylime-$(HELM_CHART_KEYLIME_VERSION).tgz ## Builds the keylime helm chart

$(BUILD_ARTIFACTS_DIR)/keylime-$(HELM_CHART_KEYLIME_VERSION).tgz: $(HELM_CHART_KEYLIME_FILES)
	helm lint $(HELM_CHART_KEYLIME_DIR)
	helm dependency update $(HELM_CHART_KEYLIME_DIR)
	helm package $(HELM_CHART_KEYLIME_DIR) --version $(HELM_CHART_KEYLIME_VERSION) --app-version $(VERSION) -d $(BUILD_ARTIFACTS_DIR)

.PHONY: helm-keylime-clean
helm-keylime-clean: ## Cleans the packaged keylime helm chart
	rm -v $(BUILD_ARTIFACTS_DIR)/keylime-$(HELM_CHART_KEYLIME_VERSION).tgz 2>/dev/null || true

.PHONY: helm-keylime-undeploy
helm-keylime-undeploy: ## Undeploy the keylime helm chart
	{ \
	helm list --namespace $(HELM_CHART_NAMESPACE) | grep -q $(HELM_CHART_RELEASE_NAME) &&\
	helm uninstall $(HELM_CHART_RELEASE_NAME) --namespace $(HELM_CHART_NAMESPACE);\
	kubectl get persistentvolumeclaim/data-$(HELM_CHART_RELEASE_NAME)-mysql-0 --namespace $(HELM_CHART_NAMESPACE) > /dev/null 2>&1 &&\
	kubectl delete persistentvolumeclaim/data-$(HELM_CHART_RELEASE_NAME)-mysql-0 --namespace $(HELM_CHART_NAMESPACE);\
	kubectl get secret/$(HELM_CHART_RELEASE_NAME)-keylime-ca-password --namespace $(HELM_CHART_NAMESPACE) > /dev/null 2>&1 &&\
	kubectl delete secret/$(HELM_CHART_RELEASE_NAME)-keylime-ca-password --namespace $(HELM_CHART_NAMESPACE);\
	kubectl get secret/$(HELM_CHART_RELEASE_NAME)-keylime-mysql-password --namespace $(HELM_CHART_NAMESPACE) > /dev/null 2>&1 &&\
	kubectl delete secret/$(HELM_CHART_RELEASE_NAME)-keylime-mysql-password --namespace $(HELM_CHART_NAMESPACE);\
	kubectl get secret/$(HELM_CHART_RELEASE_NAME)-keylime-certs --namespace $(HELM_CHART_NAMESPACE) > /dev/null 2>&1 &&\
	kubectl delete secret/$(HELM_CHART_RELEASE_NAME)-keylime-certs --namespace $(HELM_CHART_NAMESPACE);\
	kubectl get secret/$(HELM_CHART_RELEASE_NAME)-keylime-tpm-cert-store --namespace $(HELM_CHART_NAMESPACE) > /dev/null 2>&1 &&\
	kubectl delete secret/$(HELM_CHART_RELEASE_NAME)-keylime-tpm-cert-store --namespace $(HELM_CHART_NAMESPACE);\
	kubectl get secret/$(HELM_CHART_RELEASE_NAME)-keylime-tpm-extra-cert-store --namespace $(HELM_CHART_NAMESPACE) > /dev/null 2>&1 &&\
	kubectl delete secret/$(HELM_CHART_RELEASE_NAME)-keylime-tpm-extra-cert-store --namespace $(HELM_CHART_NAMESPACE);\
	rm -f $(MKFILE_DIR)/kt;\
	}

.PHONY: helm-keylime-deploy
helm-keylime-deploy: ## Deploy the keylime helm chart
	{ \
	touch $(HELM_CHART_CUSTOM_VALUES);\
	cat $(HACK_DIR)/k8s-poc/admin/keylime_tenant | sed -e "s/source/#source/g" -e "s/#export/export/g" -e "s/announce/echo/g" -e "s/REPLACE_KEYLIME_NAMESPACE/$(HELM_CHART_NAMESPACE)/g" -e "s^bin/kt^bin/keylime_tenant^g" > $(MKFILE_DIR)/kt;\
	chmod +x $(MKFILE_DIR)/kt;\
	helm install $(HELM_CHART_RELEASE_NAME) $(BUILD_ARTIFACTS_DIR)/keylime-$(HELM_CHART_KEYLIME_VERSION).tgz --namespace $(HELM_CHART_NAMESPACE) --create-namespace -f $(HELM_CHART_CUSTOM_VALUES);\
	}

.PHONY: helm-keylime-update
helm-keylime-update: ## Update the deployed keylime helm chart
	{ \
	touch $(HELM_CHART_CUSTOM_VALUES);\
	helm upgrade $(HELM_CHART_RELEASE_NAME) $(BUILD_ARTIFACTS_DIR)/keylime-$(HELM_CHART_KEYLIME_VERSION).tgz --namespace $(HELM_CHART_NAMESPACE) --create-namespace -f $(HELM_CHART_CUSTOM_VALUES);\
	}

.PHONY: helm-keylime-debug
helm-keylime-debug: ## Attempt to debug the keylime helm chart, without deploying it
	{ \
	touch $(HELM_CHART_CUSTOM_VALUES);\
	helm install $(HELM_CHART_RELEASE_NAME) $(BUILD_ARTIFACTS_DIR)/keylime-$(HELM_CHART_KEYLIME_VERSION).tgz --namespace $(HELM_CHART_NAMESPACE) --create-namespace --debug --dry-run -f $(HELM_CHART_CUSTOM_VALUES)>$(HELM_CHART_DEBUG_FILE);\
	}

.PHONY: helm-keylime-push
helm-keylime-push: helm ## Builds AND pushes the keylime helm chart
	helm push $(BUILD_ARTIFACTS_DIR)/keylime-$(HELM_CHART_KEYLIME_VERSION).tgz oci://$(HELM_CHART_REPO)
