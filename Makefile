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

# NOTE: this will change once we add the operator
VERSION ?= latest

GIT_COMMIT = $(shell git rev-parse HEAD)
GIT_DIRTY  = $(shell test -n "`git status --porcelain`" && echo "dirty" || echo "clean")
BUILD_DATE = $(shell date -u -Iseconds)

DOCKER_BUILDX_FLAGS ?=
#DOCKER_PLATFORMS ?= linux/amd64,linux/arm64
DOCKER_PLATFORMS ?= linux/amd64
DOCKER_TAG ?= quay.io/keylime/keylime_attestation_operator:$(VERSION)

# helm chart version must be semver 2 compliant
HELM_CHART_KEYLIME_VERSION ?= 0.1.0
HELM_CHART_KEYLIME_DIR := $(BUILD_DIR)/helm/keylime
HELM_CHART_KEYLIME_FILES := $(shell find $(HELM_CHART_KEYLIME_DIR) -type f)
HELM_CHART_REPO ?= ghcr.io/keylime/helm-charts

# ENVTEST_K8S_VERSION refers to the version of kubebuilder assets to be downloaded by envtest binary.
ENVTEST_K8S_VERSION = 1.27.3

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

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
KUSTOMIZE_VERSION ?= v5.0.3
CONTROLLER_TOOLS_VERSION ?= v0.12.0

install-dependencies: kustomize controller-gen envtest ## Downloads and installs all dependencies to LOCALBIN

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

helm: helm-keylime ## Builds all helm charts

.PHONY: helm-clean
helm-clean: helm-keylime-clean ## Cleans all packaged helm charts

helm-keylime: $(BUILD_ARTIFACTS_DIR)/keylime-$(HELM_CHART_KEYLIME_VERSION).tgz ## Builds the keylime helm chart

$(BUILD_ARTIFACTS_DIR)/keylime-$(HELM_CHART_KEYLIME_VERSION).tgz: $(HELM_CHART_KEYLIME_FILES)
	helm lint $(HELM_CHART_KEYLIME_DIR)
	helm package $(HELM_CHART_KEYLIME_DIR) --version $(HELM_CHART_KEYLIME_VERSION) --app-version $(VERSION) -d $(BUILD_ARTIFACTS_DIR)

.PHONY: helm-keylime-clean
helm-keylime-clean: ## Cleans the packaged keylime helm chart
	rm -v $(BUILD_ARTIFACTS_DIR)/keylime-$(HELM_CHART_KEYLIME_VERSION).tgz 2>/dev/null || true

.PHONY: helm-keylime-push
helm-keylime-push: helm ## Builds AND pushes the keylime helm chart
	helm push $(BUILD_ARTIFACTS_DIR)/keylime-$(HELM_CHART_KEYLIME_VERSION).tgz oci://$(HELM_CHART_REPO)
