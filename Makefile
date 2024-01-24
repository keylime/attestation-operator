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

GIT_COMMIT = $(shell git rev-parse HEAD)
GIT_DIRTY  = $(shell test -n "`git status --porcelain`" && echo "dirty" || echo "clean")
BUILD_DATE = $(shell date -u -Iseconds)

DOCKER_BUILDX_FLAGS ?=
#DOCKER_PLATFORMS ?= linux/amd64,linux/arm64
DOCKER_PLATFORMS ?= linux/amd64
DOCKER_NO_VERSION_TAG ?= quay.io/keylime/keylime_attestation_operator
DOCKER_TAG ?= $(DOCKER_NO_VERSION_TAG):$(VERSION)

# helm chart version must be semver 2 compliant
HELM_CHART_REPO ?= ghcr.io/keylime/helm-charts
HELM_CHART_KUBECONFIG ?= ~/.kube/config
HELM_CHART_KEYLIME_VERSION ?= 0.1.0
HELM_CHART_RELEASE_NAME ?= hhkl
HELM_CHART_NAMESPACE ?= keylime
HELM_CHART_CUSTOM_VALUES ?= values.yaml
HELM_CHART_DEBUG_FILE ?= /tmp/keylime.helm.debug
HELM_CHART_KEYLIME_DIR := $(BUILD_DIR)/helm/keylime
HELM_CHART_KEYLIME_FILES := $(shell find $(HELM_CHART_KEYLIME_DIR) -type f)
HELM_CHART_CRDS_VERSION ?= 0.1.0
HELM_CHART_CRDS_DIR := $(BUILD_DIR)/helm/keylime-crds
HELM_CHART_CRDS_FILES := $(shell find $(HELM_CHART_CRDS_DIR) -type f)
HELM_CHART_CRDS_FILES += $(shell find $(MKFILE_DIR)/config/crd -type f)
HELM_CHART_CONTROLLER_VERSION ?= 0.1.0
HELM_CHART_CONTROLLER_DIR := $(BUILD_DIR)/helm/keylime-controller
HELM_CHART_CONTROLLER_FILES := $(shell find $(HELM_CHART_CONTROLLER_DIR) -type f)
HELM_CHART_CONTROLLER_FILES += $(shell find $(MKFILE_DIR)/config/helm -type f)

# ENVTEST_K8S_VERSION refers to the version of kubebuilder assets to be downloaded by envtest binary.
ENVTEST_K8S_VERSION = 1.27.3

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# Bundle version does not accept "latest", it must contain something similar to vMajor.Minor.Patch
BUNDLE_VERSION ?= $(VERSION)
ifeq ($(BUNDLE_VERSION),latest)
	BUNDLE_VERSION=$(HELM_CHART_CONTROLLER_VERSION)
endif

# Bundle related information
# CHANNELS define the bundle channels used in the bundle.
# Add a new line here if you would like to change its default config. (E.g CHANNELS = "candidate,fast,stable")
# To re-generate a bundle for other specific channels without changing the standard setup, you can:
# - use the CHANNELS as arg of the bundle target (e.g make bundle CHANNELS=candidate,fast,stable)
# - use environment variables to overwrite this value (e.g export CHANNELS="candidate,fast,stable")
ifneq ($(origin CHANNELS), undefined)
BUNDLE_CHANNELS := --channels=$(CHANNELS)
endif

# DEFAULT_CHANNEL defines the default channel used in the bundle.
# Add a new line here if you would like to change its default config. (E.g DEFAULT_CHANNEL = "stable")
# To re-generate a bundle for any other default channel without changing the default setup, you can:
# - use the DEFAULT_CHANNEL as arg of the bundle target (e.g make bundle DEFAULT_CHANNEL=stable)
# - use environment variables to overwrite this value (e.g export DEFAULT_CHANNEL="stable")
DEFAULT_CHANNEL ?= stable
ifneq ($(origin DEFAULT_CHANNEL), undefined)
BUNDLE_DEFAULT_CHANNEL := --default-channel=$(DEFAULT_CHANNEL)
endif
BUNDLE_METADATA_OPTS ?= $(BUNDLE_CHANNELS) $(BUNDLE_DEFAULT_CHANNEL)

# BUNDLE_IMG defines the image:tag used for the bundle.
# You can use it as an arg. (E.g make bundle-build BUNDLE_IMG=<some-registry>/<project-name-bundle>:<tag>)
BUNDLE_IMG ?= $(DOCKER_NO_VERSION_TAG)-bundle:$(BUNDLE_VERSION)

# BUNDLE_GEN_FLAGS are the flags passed to the operator-sdk generate bundle command
BUNDLE_GEN_FLAGS ?= -q --overwrite --version $(BUNDLE_VERSION) $(BUNDLE_METADATA_OPTS)

# USE_IMAGE_DIGESTS defines if images are resolved via tags or digests
# You can enable this value if you would like to use SHA Based Digests
# To enable set flag to true
USE_IMAGE_DIGESTS ?= false
ifeq ($(USE_IMAGE_DIGESTS), true)
	BUNDLE_GEN_FLAGS += --use-image-digests
endif

# Set the Operator SDK version to use. By default, what is installed on the system is used.
# This is useful for CI or a project to utilize a specific version of the operator-sdk toolkit.
OPERATOR_SDK_VERSION ?= v1.33.0


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

all: help

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: manifests
manifests: controller-gen ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	$(CONTROLLER_GEN) rbac:roleName=manager-role crd webhook paths="./..." output:crd:artifacts:config=config/crd/bases

.PHONY: generate
generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test
test: manifests generate fmt vet envtest ## Run tests.
	KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path)" go test ./... -coverprofile cover.out

.PHONY: build
build: manifests generate fmt vet ## Build manager binary.
	go build -o $(BUILD_ARTIFACTS_DIR)/attestation-operator ./cmd/attestation-operator

.PHONY: run
run: manifests generate fmt vet ## Run a controller from your host.
	go run ./cmd/attestation-operator

##@ Development Deployment

ifndef ignore-not-found
ignore-not-found = false
endif

.PHONY: install
install: manifests kustomize ## Install CRDs into the K8s cluster specified in ~/.kube/config.
	$(KUSTOMIZE) build config/crd | $(KUBECTL) apply -f -

.PHONY: uninstall
uninstall: manifests kustomize ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUSTOMIZE) build config/crd | $(KUBECTL) delete --ignore-not-found=$(ignore-not-found) -f -

.PHONY: deploy
deploy: manifests kustomize ## Deploy controller to the K8s cluster specified in ~/.kube/config.
	cd config/manager && $(KUSTOMIZE) edit set image controller=$(DOCKER_TAG)
	$(KUSTOMIZE) build config/default | $(KUBECTL) apply -f -

.PHONY: undeploy
undeploy: ## Undeploy controller from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUSTOMIZE) build config/default | $(KUBECTL) delete --ignore-not-found=$(ignore-not-found) -f -

##@ Development Build Dependencies

## Location to install dependencies to
LOCALBIN ?= $(MKFILE_DIR)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

## Tool Binaries
KUBECTL ?= kubectl
KUSTOMIZE ?= $(LOCALBIN)/kustomize
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
ENVTEST ?= $(LOCALBIN)/setup-envtest

## Tool Versions
HELMIFY ?= $(LOCALBIN)/helmify
KUSTOMIZE_VERSION ?= v5.0.3
CONTROLLER_TOOLS_VERSION ?= v0.12.0

install-dependencies: kustomize controller-gen envtest helmify ## Downloads and installs all dependencies to LOCALBIN

.PHONY: clean-dependencies
clean-dependencies: ## Removes all downloaded dependencies from LOCALBIN
	rm -v $(KUSTOMIZE) 2>/dev/null || true
	rm -v $(CONTROLLER_GEN) 2>/dev/null || true
	rm -v $(ENVTEST) 2>/dev/null || true

.PHONY: kustomize
kustomize: $(KUSTOMIZE) ## Download kustomize locally if necessary. If wrong version is installed, it will be removed before downloading.
$(KUSTOMIZE): $(LOCALBIN)
	@if test -x $(LOCALBIN)/kustomize && ! $(LOCALBIN)/kustomize version | grep -q $(KUSTOMIZE_VERSION); then \
		echo "$(LOCALBIN)/kustomize version is not expected $(KUSTOMIZE_VERSION). Removing it before installing."; \
		rm -rf $(LOCALBIN)/kustomize; \
	fi
	test -s $(LOCALBIN)/kustomize || GOBIN=$(LOCALBIN) GO111MODULE=on go install sigs.k8s.io/kustomize/kustomize/v5@$(KUSTOMIZE_VERSION)

.PHONY: controller-gen
controller-gen: $(CONTROLLER_GEN) ## Download controller-gen locally if necessary. If wrong version is installed, it will be overwritten.
$(CONTROLLER_GEN): $(LOCALBIN)
	test -s $(LOCALBIN)/controller-gen && $(LOCALBIN)/controller-gen --version | grep -q $(CONTROLLER_TOOLS_VERSION) || \
	GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_TOOLS_VERSION)

.PHONY: envtest
envtest: $(ENVTEST) ## Download envtest-setup locally if necessary.
$(ENVTEST): $(LOCALBIN)
	test -s $(LOCALBIN)/setup-envtest || GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest

.PHONY: helmify
helmify: $(HELMIFY) ## Download helmify locally if necessary.
$(HELMIFY): $(LOCALBIN)
	test -s $(LOCALBIN)/helmify || GOBIN=$(LOCALBIN) go install github.com/arttor/helmify/cmd/helmify@latest

##@ Build

.PHONY: docker-build
docker-build: ## Builds the application in a docker container and creates a docker image
	docker buildx build \
		-f $(MKFILE_DIR)/build/docker/attestation-operator/Dockerfile \
		-t $(DOCKER_TAG) \
		--progress=plain \
		--build-arg APPVERSION=$(VERSION) \
		--build-arg GITCOMMIT=$(GIT_COMMIT) \
		--build-arg GITTREESTATE=$(GIT_DIRTY) \
		--build-arg BUILDDATE=$(BUILD_DATE) \
		--platform=$(DOCKER_PLATFORMS) $(DOCKER_BUILDX_FLAGS) \
		. 2>&1

.PHONY: docker-push
docker-push: ## Pushes a previously built docker container
	docker push $(DOCKER_TAG)

helm: helm-keylime helm-crds helm-controller ## Builds all helm charts

.PHONY: helm-build
helm-build: helm-keylime

.PHONY: helm-clean
helm-clean: helm-keylime-clean helm-crds-clean helm-controller-clean ## Cleans all packaged helm charts

.PHONY: helm-undeploy
helm-undeploy: helm-keylime-undeploy

.PHONY: helm-deploy
helm-deploy: helm-keylime-deploy

.PHONY: helm-update
helm-deploy: helm-keylime-update

.PHONY: helm-debug
helm-debug: helm-keylime-debug

.PHONY: helm-test
helm-deploy: helm-keylime-test

helm-keylime: $(BUILD_ARTIFACTS_DIR)/keylime-$(HELM_CHART_KEYLIME_VERSION).tgz ## Builds the keylime helm chart

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
	helm list --namespace $(HELM_CHART_NAMESPACE) --kubeconfig $(HELM_CHART_KUBECONFIG) | grep -q $(HELM_CHART_RELEASE_NAME) &&\
	helm uninstall $(HELM_CHART_RELEASE_NAME) --namespace $(HELM_CHART_NAMESPACE) --kubeconfig $(HELM_CHART_KUBECONFIG);\
	kubectl --kubeconfig $(HELM_CHART_KUBECONFIG) get persistentvolumeclaim/data-$(HELM_CHART_RELEASE_NAME)-mysql-0 --namespace $(HELM_CHART_NAMESPACE) > /dev/null 2>&1 &&\
	kubectl --kubeconfig $(HELM_CHART_KUBECONFIG) delete persistentvolumeclaim/data-$(HELM_CHART_RELEASE_NAME)-mysql-0 --namespace $(HELM_CHART_NAMESPACE);\
	kubectl --kubeconfig $(HELM_CHART_KUBECONFIG) get secret/$(HELM_CHART_RELEASE_NAME)-keylime-ca-password --namespace $(HELM_CHART_NAMESPACE) > /dev/null 2>&1 &&\
	kubectl --kubeconfig $(HELM_CHART_KUBECONFIG) delete secret/$(HELM_CHART_RELEASE_NAME)-keylime-ca-password --namespace $(HELM_CHART_NAMESPACE);\
	kubectl --kubeconfig $(HELM_CHART_KUBECONFIG) get secret/$(HELM_CHART_RELEASE_NAME)-keylime-mysql-password --namespace $(HELM_CHART_NAMESPACE) > /dev/null 2>&1 &&\
	kubectl --kubeconfig $(HELM_CHART_KUBECONFIG) delete secret/$(HELM_CHART_RELEASE_NAME)-keylime-mysql-password --namespace $(HELM_CHART_NAMESPACE);\
	kubectl --kubeconfig $(HELM_CHART_KUBECONFIG) get secret/$(HELM_CHART_RELEASE_NAME)-keylime-certs --namespace $(HELM_CHART_NAMESPACE) > /dev/null 2>&1 &&\
	kubectl --kubeconfig $(HELM_CHART_KUBECONFIG) delete secret/$(HELM_CHART_RELEASE_NAME)-keylime-certs --namespace $(HELM_CHART_NAMESPACE);\
	kubectl --kubeconfig $(HELM_CHART_KUBECONFIG) get secret/$(HELM_CHART_RELEASE_NAME)-keylime-tpm-cert-store --namespace $(HELM_CHART_NAMESPACE) > /dev/null 2>&1 &&\
	kubectl --kubeconfig $(HELM_CHART_KUBECONFIG) delete secret/$(HELM_CHART_RELEASE_NAME)-keylime-tpm-cert-store --namespace $(HELM_CHART_NAMESPACE);\
	kubectl --kubeconfig $(HELM_CHART_KUBECONFIG) get secret/$(HELM_CHART_RELEASE_NAME)-keylime-tpm-extra-cert-store --namespace $(HELM_CHART_NAMESPACE) > /dev/null 2>&1 &&\
	kubectl --kubeconfig $(HELM_CHART_KUBECONFIG) delete secret/$(HELM_CHART_RELEASE_NAME)-keylime-tpm-extra-cert-store --namespace $(HELM_CHART_NAMESPACE);\
	kubectl --kubeconfig $(HELM_CHART_KUBECONFIG) get job/$(HELM_CHART_RELEASE_NAME)-keylime-init-ca --namespace $(HELM_CHART_NAMESPACE) > /dev/null 2>&1 &&\
	kubectl --kubeconfig $(HELM_CHART_KUBECONFIG) delete job/$(HELM_CHART_RELEASE_NAME)-keylime-init-ca --namespace $(HELM_CHART_NAMESPACE);\
	rm -f $(MKFILE_DIR)/kt;\
	}

.PHONY: helm-keylime-deploy
helm-keylime-deploy: ## Deploy the keylime helm chart
	{ \
	touch $(HELM_CHART_CUSTOM_VALUES);\
	cat $(HACK_DIR)/k8s-poc/admin/kt | sed -e "s/#export/export/g" -e "s^REPLACE_HELM_CHART_KUBECONFIG^$(HELM_CHART_KUBECONFIG)^g" -e "s/REPLACE_KEYLIME_NAMESPACE/$(HELM_CHART_NAMESPACE)/g" > $(MKFILE_DIR)/kt;\
	chmod +x $(MKFILE_DIR)/kt;\
	helm install $(HELM_CHART_RELEASE_NAME) $(BUILD_ARTIFACTS_DIR)/keylime-$(HELM_CHART_KEYLIME_VERSION).tgz --namespace $(HELM_CHART_NAMESPACE) --create-namespace --kubeconfig $(HELM_CHART_KUBECONFIG) -f $(HELM_CHART_CUSTOM_VALUES);\
	}

.PHONY: helm-keylime-update
helm-keylime-update: ## Update the deployed keylime helm chart
	{ \
	touch $(HELM_CHART_CUSTOM_VALUES);\
	cat $(HACK_DIR)/k8s-poc/admin/kt | sed -e "s/#export/export/g" -e "s^REPLACE_HELM_CHART_KUBECONFIG^$(HELM_CHART_KUBECONFIG)^g" -e "s/REPLACE_KEYLIME_NAMESPACE/$(HELM_CHART_NAMESPACE)/g" > $(MKFILE_DIR)/kt;\
	chmod +x $(MKFILE_DIR)/kt;\
	helm upgrade $(HELM_CHART_RELEASE_NAME) $(BUILD_ARTIFACTS_DIR)/keylime-$(HELM_CHART_KEYLIME_VERSION).tgz --namespace $(HELM_CHART_NAMESPACE) --create-namespace --kubeconfig $(HELM_CHART_KUBECONFIG) -f $(HELM_CHART_CUSTOM_VALUES);\
	}

.PHONY: helm-keylime-debug
helm-keylime-debug: ## Attempt to debug the keylime helm chart, without deploying it
	{ \
	touch $(HELM_CHART_CUSTOM_VALUES);\
	helm install $(HELM_CHART_RELEASE_NAME) $(BUILD_ARTIFACTS_DIR)/keylime-$(HELM_CHART_KEYLIME_VERSION).tgz --namespace $(HELM_CHART_NAMESPACE) --create-namespace --debug --dry-run --kubeconfig $(HELM_CHART_KUBECONFIG) -f $(HELM_CHART_CUSTOM_VALUES)>$(HELM_CHART_DEBUG_FILE);\
	}

.PHONY: helm-keylime-push
helm-keylime-push: helm-keylime ## Builds AND pushes the keylime helm chart
	helm push $(BUILD_ARTIFACTS_DIR)/keylime-$(HELM_CHART_KEYLIME_VERSION).tgz oci://$(HELM_CHART_REPO)

.PHONY: helm-keylime-test
helm-keylime-test: ## Basic testing for the keylime helm chart
	{ \
	touch $(HELM_CHART_CUSTOM_VALUES);\
	cat $(HACK_DIR)/k8s-poc/admin/kt | sed -e "s/#export/export/g" -e "s^REPLACE_HELM_CHART_KUBECONFIG^$(HELM_CHART_KUBECONFIG)^g" -e "s/REPLACE_KEYLIME_NAMESPACE/$(HELM_CHART_NAMESPACE)/g" > $(MKFILE_DIR)/kt;\
	chmod +x $(MKFILE_DIR)/kt;\
	touch /tmp/empty;\
	./kt -c reglist && ./kt -c deleteall && ./kt -c addall -f /tmp/empty;\
	}

helm-crds: $(BUILD_ARTIFACTS_DIR)/keylime-crds-$(HELM_CHART_CRDS_VERSION).tgz ## Builds the keylime-crds helm chart

$(BUILD_ARTIFACTS_DIR)/keylime-crds-$(HELM_CHART_CRDS_VERSION).tgz: $(HELM_CHART_CRDS_FILES) manifests kustomize helmify
	$(KUSTOMIZE) build config/crd | $(HELMIFY) -v $(HELM_CHART_CRDS_DIR)
	helm lint $(HELM_CHART_CRDS_DIR)
	helm package $(HELM_CHART_CRDS_DIR) --version $(HELM_CHART_CRDS_VERSION) --app-version $(VERSION) -d $(BUILD_ARTIFACTS_DIR)

.PHONY: helm-crds-clean
helm-crds-clean: ## Cleans the packaged keylime-crds helm chart
	rm -v $(BUILD_ARTIFACTS_DIR)/keylime-crds-$(HELM_CHART_CRDS_VERSION).tgz 2>/dev/null || true

.PHONY: helm-crds-push
helm-crds-push: helm-crds ## Builds AND pushes the keylime-crds helm chart
	helm push $(BUILD_ARTIFACTS_DIR)/keylime-crds-$(HELM_CHART_CRDS_VERSION).tgz oci://$(HELM_CHART_REPO)

helm-controller: $(BUILD_ARTIFACTS_DIR)/keylime-controller-$(HELM_CHART_CONTROLLER_VERSION).tgz ## Builds the keylime-controller helm chart

$(BUILD_ARTIFACTS_DIR)/keylime-controller-$(HELM_CHART_CONTROLLER_VERSION).tgz: $(HELM_CHART_CONTROLLER_FILES) manifests kustomize helmify
	$(KUSTOMIZE) build config/helm | $(HELMIFY) -v $(HELM_CHART_CONTROLLER_DIR)
	helm lint $(HELM_CHART_CONTROLLER_DIR)
	helm package $(HELM_CHART_CONTROLLER_DIR) --version $(HELM_CHART_CONTROLLER_VERSION) --app-version $(VERSION) -d $(BUILD_ARTIFACTS_DIR)

.PHONY: helm-controller-clean ## Cleans the packaged keylime-controller helm chart
helm-controller-clean:
	rm -v $(BUILD_ARTIFACTS_DIR)/keylime-controller-$(HELM_CHART_CONTROLLER_VERSION).tgz 2>/dev/null || true

.PHONY: helm-controller-push
helm-controller-push: helm-controller ## Builds AND pushes the keylime-controller helm chart
	helm push $(BUILD_ARTIFACTS_DIR)/keylime-controller-$(HELM_CHART_CONTROLLER_VERSION).tgz oci://$(HELM_CHART_REPO)

.PHONY: operator-sdk
OPERATOR_SDK ?= $(LOCALBIN)/operator-sdk
operator-sdk: ## Download operator-sdk locally if necessary.
ifeq (,$(wildcard $(OPERATOR_SDK)))
ifeq (, $(shell which operator-sdk 2>/dev/null))
	@{ \
	set -e ;\
	mkdir -p $(dir $(OPERATOR_SDK)) ;\
	OS=$(shell go env GOOS) && ARCH=$(shell go env GOARCH) && \
	curl -sSLo $(OPERATOR_SDK) https://github.com/operator-framework/operator-sdk/releases/download/$(OPERATOR_SDK_VERSION)/operator-sdk_$${OS}_$${ARCH} ;\
	chmod +x $(OPERATOR_SDK) ;\
	}
else
OPERATOR_SDK = $(shell which operator-sdk)
endif
endif

.PHONY: bundle
bundle: manifests kustomize operator-sdk ## Generate bundle manifests and metadata, then validate generated files.
	$(OPERATOR_SDK) generate kustomize manifests -q
	cd config/manager && $(KUSTOMIZE) edit set image controller=$(DOCKER_TAG)
	$(KUSTOMIZE) build config/manifests | $(OPERATOR_SDK) generate bundle $(BUNDLE_GEN_FLAGS)
	$(OPERATOR_SDK) bundle validate ./bundle

.PHONY: bundle-build
bundle-build: ## Build the bundle image.
	docker build -f bundle.Dockerfile -t $(BUNDLE_IMG) .

.PHONY: bundle-push
bundle-push: ## Push the bundle image.
	$(MAKE) docker-push DOCKER_TAG=$(BUNDLE_IMG)

.PHONY: opm
OPM = ./bin/opm
opm: ## Download opm locally if necessary.
ifeq (,$(wildcard $(OPM)))
ifeq (,$(shell which opm 2>/dev/null))
	@{ \
	set -e ;\
	mkdir -p $(dir $(OPM)) ;\
	OS=$(shell go env GOOS) && ARCH=$(shell go env GOARCH) && \
	curl -sSLo $(OPM) https://github.com/operator-framework/operator-registry/releases/download/v1.23.0/$${OS}-$${ARCH}-opm ;\
	chmod +x $(OPM) ;\
	}
else
OPM = $(shell which opm)
endif
endif

# A comma-separated list of bundle images (e.g. make catalog-build BUNDLE_IMGS=example.com/operator-bundle:v0.1.0,example.com/operator-bundle:v0.2.0).
# These images MUST exist in a registry and be pull-able.
BUNDLE_IMGS ?= $(BUNDLE_IMG)

# The image tag given to the resulting catalog image (e.g. make catalog-build CATALOG_IMG=example.com/operator-catalog:v0.2.0).
CATALOG_IMG ?= $(IMAGE_TAG_BASE)-catalog:v$(VERSION)

# Set CATALOG_BASE_IMG to an existing catalog image tag to add $BUNDLE_IMGS to that image.
ifneq ($(origin CATALOG_BASE_IMG), undefined)
FROM_INDEX_OPT := --from-index $(CATALOG_BASE_IMG)
endif

# Build a catalog image by adding bundle images to an empty catalog using the operator package manager tool, 'opm'.
# This recipe invokes 'opm' in 'semver' bundle add mode. For more information on add modes, see:
# https://github.com/operator-framework/community-operators/blob/7f1438c/docs/packaging-operator.md#updating-your-existing-operator
.PHONY: catalog-build
catalog-build: opm ## Build a catalog image.
	$(OPM) index add --container-tool docker --mode semver --tag $(CATALOG_IMG) --bundles $(BUNDLE_IMGS) $(FROM_INDEX_OPT)

# Push the catalog image.
.PHONY: catalog-push
catalog-push: ## Push a catalog image.
	$(MAKE) docker-push DOCKER_TAG=$(CATALOG_IMG)
