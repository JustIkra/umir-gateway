# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.26.9-alpine AS build
WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG TARGETOS
ARG TARGETARCH
RUN --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server

FROM scratch AS runtime
WORKDIR /app
COPY --link --from=build /out/server /server
COPY --link --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENV TZ=Europe/Moscow PORT=8080
LABEL org.opencontainers.image.source="https://github.com/JustIkra/umir-gateway"
USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 CMD ["/server", "healthcheck"]
ENTRYPOINT ["/server"]

