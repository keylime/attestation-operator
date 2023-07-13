# Build the manager binary
FROM golang:1.20 as builder
ARG TARGETOS
ARG TARGETARCH
ARG APPVERSION=dev
ARG GITCOMMIT=dev
ARG GITTREESTATE=dev
ARG BUILDDATE=dev

WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source
COPY cmd/ cmd/
COPY api/ api/
COPY internal/ internal/
COPY pkg/ pkg/

# Build
# the GOARCH has not a default value to allow the binary be built according to the host where the command
# was called. For example, if we call make docker-build in a local env which has the Apple Silicon M1 SO
# the docker BUILDPLATFORM arg will be linux/arm64 when for Apple x86 it will be linux/amd64. Therefore,
# by leaving it empty we can ensure that the container and binary shipped on it will have the same platform.
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -a -o attestation-operator -ldflags="-w -s -X 'github.com/keylime/attestation-operator/pkg/version.version=${APPVERSION}' -X 'github.com/keylime/attestation-operator/pkg/version.gitCommit=${GITCOMMIT}' -X 'github.com/keylime/attestation-operator/pkg/version.gitTreeState=${GITTREESTATE}' -X 'github.com/keylime/attestation-operator/pkg/version.buildDate=${BUILDDATE}'" ./cmd/attestation-operator

# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/attestation-operator /bin/attestation-operator
USER 65532:65532

ENTRYPOINT ["/bin/attestation-operator"]

LABEL org.opencontainers.image.authors="Keylime Team <main@keylime.groups.io>"
LABEL org.opencontainers.image.version="$APPVERSION"
LABEL org.opencontainers.image.title="Kubernetes Attestation Operator"
LABEL org.opencontainers.image.description="The Keylime Attestation Operator manages keylime through Kubernetes APIs"
LABEL org.opencontainers.image.url="https://keylime.dev/"
LABEL org.opencontainers.image.source="https://github.com/keylime/attestation-operator/"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.vendor="The Keylime Authors"
