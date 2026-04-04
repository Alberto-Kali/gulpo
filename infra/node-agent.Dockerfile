FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY apps/node-agent/go.mod apps/node-agent/go.sum* ./apps/node-agent/
WORKDIR /src/apps/node-agent
RUN go mod download
COPY apps/node-agent ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/node-agent ./cmd/node-agent

FROM ghcr.io/sagernet/sing-box:latest
WORKDIR /app
COPY --from=builder /out/node-agent /usr/local/bin/node-agent
ENTRYPOINT ["/usr/local/bin/node-agent"]

