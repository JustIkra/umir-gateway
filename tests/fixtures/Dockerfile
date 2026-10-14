# syntax=docker/dockerfile:1
FROM golang:1.26.9-alpine@sha256:3082400e369fa24d5fc60bca20edab3f6d604e0c5a690ec66b295eff4dd87ade AS build
WORKDIR /app
ENV GOWORK=off CGO_ENABLED=0
COPY go.mod go.sum ./
RUN go mod download
COPY internal ./internal
COPY tests/fixtures ./tests/fixtures
RUN go run ./tests/fixtures/catalog/build fixture-manifest
RUN go build -trimpath -ldflags "-X github.com/JustIkra/umir-gateway/tests/fixtures/catalog.fixtureSHA256=$(cat /out/fixture-source.sha)" -o /out/fixture-server ./tests/fixtures/server && go build -trimpath -o /out/fixture-control ./tests/fixtures/control
RUN go run ./tests/fixtures/catalog/build
RUN mkdir -p /out/run/umir-fixtures && chmod 0700 /out/run/umir-fixtures
FROM scratch AS runtime
WORKDIR /app
COPY --from=build /out/fixture-server /fixture-server
COPY --from=build /out/fixture-control /fixture-control
COPY --from=build /out/zoneinfo.zip /usr/local/lib/umir/zoneinfo.zip
COPY --from=build /out/catalog-provenance.json /usr/local/lib/umir/catalog-provenance.json
COPY --from=build /out/fixture-source.json /usr/local/lib/umir/fixture-source.json
COPY --from=build /out/fixture-source-manifest.json /usr/local/lib/umir/fixture-source-manifest.json
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chown=65532:65532 /out/run /run
ENV TZ=Europe/Moscow
LABEL org.opencontainers.image.source="https://github.com/JustIkra/umir-gateway" io.umir.fixture.owner="gateway"
USER 65532:65532
EXPOSE 8080 8082
HEALTHCHECK --interval=10s --timeout=10s --start-period=10s --retries=3 CMD ["/fixture-server", "healthcheck"]
ENTRYPOINT ["/fixture-server"]
CMD ["serve"]
