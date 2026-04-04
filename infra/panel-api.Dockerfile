FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY apps/panel-api/go.mod apps/panel-api/go.sum* ./apps/panel-api/
WORKDIR /src/apps/panel-api
RUN go mod download
COPY apps/panel-api ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/panel-api ./cmd/panel-api

FROM alpine:3.20
RUN adduser -D app
USER app
WORKDIR /app
COPY --from=builder /out/panel-api /app/panel-api
COPY apps/panel-api/migrations /app/migrations
EXPOSE 8080
ENTRYPOINT ["/app/panel-api"]

