# Этап сборки
FROM golang:1.24 AS builder

WORKDIR /copy-detector

COPY go.mod go.sum ./
COPY cmd ./cmd
COPY internal ./internal

RUN go mod download
ENTRYPOINT go run ./cmd/copy-detector -address $GROUP_ADDRESS -port $GROUP_PORT

// перересоваывается терминал
// выбор интеерфейса
// в таблице не только ip но и порт