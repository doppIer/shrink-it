# syntax=docker/dockerfile:1

# Build on the runner's native platform and cross-compile for the target,
# so multi-arch builds don't run the Go compiler under QEMU emulation.
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/shrink-it ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot
ARG VERSION=dev
LABEL org.opencontainers.image.title="shrink-it" \
      org.opencontainers.image.description="Self-hosted URL shortener with smart routing, safety scanning and dead-link fallback" \
      org.opencontainers.image.source="https://github.com/doppIer/shrink-it" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"
COPY --from=build /out/shrink-it /shrink-it
COPY blocklist.txt /etc/shrink-it/blocklist.txt
ENV BLOCKLIST_PATH=/etc/shrink-it/blocklist.txt
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/shrink-it"]
