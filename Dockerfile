# syntax=docker/dockerfile:1.7

FROM golang:1.26-bookworm@sha256:9fdc884aacc3bec89b20ffc69f4bb369c78210e3e4f600387b5128b12c199f81 AS build
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
WORKDIR /src
COPY go.mod go.sum ./
RUN GOWORK=off go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} GOWORK=off \
    go build -trimpath -ldflags "-s -w -X github.com/gxbrave/AntiNAT-Agent/internal/buildinfo.Version=${VERSION} -X github.com/gxbrave/AntiNAT-Agent/internal/buildinfo.Commit=${COMMIT} -X github.com/gxbrave/AntiNAT-Agent/internal/buildinfo.Date=${BUILD_DATE}" \
    -o /out/antinat-agent ./cmd/antinat-agent

FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce
RUN addgroup -S -g 65532 antinat && adduser -S -D -H -u 65532 -G antinat antinat \
    && mkdir -p /var/lib/antinat /var/log/antinat \
    && chown -R 65532:65532 /var/lib/antinat /var/log/antinat
COPY --from=build /out/antinat-agent /opt/antinat/bin/antinat-agent
COPY docker/healthcheck-agent.sh /opt/antinat/bin/healthcheck-agent
COPY docker/stage-enrollment.sh /opt/antinat/bin/stage-enrollment
RUN chmod 0755 /opt/antinat/bin/antinat-agent /opt/antinat/bin/healthcheck-agent /opt/antinat/bin/stage-enrollment
USER 65532:65532
WORKDIR /var/lib/antinat
VOLUME ["/var/lib/antinat", "/var/log/antinat"]
LABEL org.opencontainers.image.title="AntiNAT Agent" \
      org.opencontainers.image.source="https://github.com/gxbrave/AntiNAT-Agent" \
      org.opencontainers.image.description="AntiNAT forwarding agent" \
      org.opencontainers.image.licenses="Apache-2.0"
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/opt/antinat/bin/healthcheck-agent"]
ENTRYPOINT ["/opt/antinat/bin/stage-enrollment"]
