# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.26.9-alpine AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG TARGETOS
ARG TARGETARCH
RUN --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server
# A new named volume mounted at /data/operator takes this owner and mode on first use.
RUN mkdir -p /out/data/operator

FROM scratch AS runtime
WORKDIR /app
COPY --link --from=build /out/server /server
COPY --link --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --link --from=build --chown=65532:65532 --chmod=0700 /out/data /data
ENV TZ=Europe/Moscow PORT=8080 OPERATOR_STORE_PATH=/data/operator/account.json
LABEL org.opencontainers.image.source="https://github.com/JustIkra/umir-gateway"
USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 CMD ["/server", "healthcheck"]
ENTRYPOINT ["/server"]

