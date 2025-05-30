FROM golang:1.24 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN CGO_ENABLED=1 GOOS=linux go build -a -tags netgo -ldflags '-w -extldflags "-static"' -o ai-iam cmd/server/main.go



FROM debian:bullseye-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
RUN mkdir -p /app/data
COPY --from=builder /app/ai-iam .
COPY config.json .

ENV IAM_PORT=8080
ENV IAM_DB_PATH=/app/data/iam.db
ENV IAM_CONFIG_PATH=/app/config.json

EXPOSE 8080

ENTRYPOINT ["/app/ai-iam"]