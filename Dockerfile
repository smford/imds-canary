# Multi-stage Dockerfile for imds-canary
FROM --platform=$BUILDPLATFORM golang:alpine AS builder
ENV GOTOOLCHAIN=auto

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
    -trimpath \
    -ldflags="-s -w -X github.com/smford/imds-canary/internal/version.Version=${VERSION} -X github.com/smford/imds-canary/internal/version.Commit=${COMMIT} -X github.com/smford/imds-canary/internal/version.Date=${DATE}" \
    -o /imds-canary ./cmd/imds-canary

# Final distroless nonroot image
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /
COPY --from=builder /imds-canary /usr/local/bin/imds-canary

EXPOSE 18080
USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/imds-canary"]
CMD ["-dry-run", "-port", "18080", "-bind", "0.0.0.0"]
