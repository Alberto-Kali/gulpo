FROM golang:1.23-alpine AS builder
WORKDIR /src
COPY apps/node-agent ./
WORKDIR /src
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/node-agent ./cmd/node-agent

FROM golang:1.25-alpine AS singbox-builder
RUN apk add --no-cache git build-base
RUN GOWORK=off CGO_ENABLED=0 go install -trimpath -tags 'with_v2ray_api with_quic with_clash_api' github.com/sagernet/sing-box/cmd/sing-box@v1.13.5

FROM ghcr.io/sagernet/sing-box:v1.13.5
WORKDIR /app
COPY --from=singbox-builder /go/bin/sing-box /usr/local/bin/sing-box
COPY --from=builder /out/node-agent /usr/local/bin/node-agent
ENTRYPOINT ["/usr/local/bin/node-agent"]
