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

# helm chart version must be semver 2 compliant
HELM_CHART_KEYLIME_VERSION ?= 0.1.0
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
