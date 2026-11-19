# ZUHAN: multi-stage build. Stage 1 compiles a static binary, stage 2 ships only that binary.
# Build context = the directory that contains go.mod.
FROM golang:1.24 AS build
WORKDIR /src
COPY go.mod ./
COPY . .
ARG VERSION=docker
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/zuhan ./cmd/zuhan

FROM alpine:3
# ca-certificates: required for the HTTPS calls to the intel sources
RUN apk add --no-cache ca-certificates \
 && addgroup -S zuhan && adduser -S -G zuhan zuhan \
 && mkdir -p /data /state && chown zuhan:zuhan /data /state
COPY --from=build /out/zuhan /usr/local/bin/zuhan
# Settings and the local IOC list live in /state (mount a volume there to keep them).
# API keys come from environment variables (VT_API_KEY, ABUSECH_API_KEY, OTX_API_KEY, ...).
ENV XDG_CONFIG_HOME=/state/config \
    ZUHAN_DB=/state/iocdb.json
USER zuhan
WORKDIR /data
CMD ["zuhan", "version"]
