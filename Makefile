REGISTRY := github.com/open-component-model/signing-server

ifeq ($(OS),Windows_NT)
    REPO_ROOT := $(CURDIR)
    VERSION := $(shell cat VERSION)
else
    REPO_ROOT := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
    VERSION := $(shell cat $(REPO_ROOT)/VERSION)
endif
EFFECTIVE_VERSION                := $(VERSION)-$(shell git rev-parse HEAD)

# REGISTRY                         := europe-docker.pkg.dev/gardener-project/releases
IMAGE_REPOSITORY                 := $(REGISTRY)/cicd/signing-server

PRIVATE_KEY_SECRET_NAME := private-key
CERT_CM_NAME := cert
CA_CERTS_CM_NAME := ca-certs

.PHONY: go-build
go-build:
	@go build -o signing-server ./cmd/signing-server/main.go

.PHONY: docker-build
docker-build:
	@echo "Building docker image for version $(EFFECTIVE_VERSION)"
	@docker build -t $(IMAGE_REPOSITORY):$(EFFECTIVE_VERSION) -f Dockerfile .

.PHONY: create-private-key-secret
create-private-key-secret:
	@echo "Creating secret $(PRIVATE_KEY_SECRET_NAME) which contains the private key for signing"
	@kubectl create secret generic $(PRIVATE_KEY_SECRET_NAME) --from-file=key.pem=$(PRIVATE_KEY_FILE)

.PHONY: create-cert-configmap
create-cert-configmap:
	@echo "Creating configmap $(CERT_CM_NAME) which contains the server certificate"
	@kubectl create configmap $(CERT_CM_NAME) --from-file=cert.pem=$(CERT_FILE)

.PHONY: create-ca-certs-configmap
create-ca-certs-configmap:
	@echo "Creating configmap $(CA_CERTS_CM_NAME) which contains any intermediate and ca certificates"
	@kubectl create configmap $(CA_CERTS_CM_NAME) --from-file=certs.pem=$(CA_CERTS_FILE)

.PHONY: format
format:
	@go fmt $(REPO_ROOT)/pkg/... $(REPO_ROOT)/cmd/...

.PHONY: clean
clean:
	rm -rf local/server local/signing
