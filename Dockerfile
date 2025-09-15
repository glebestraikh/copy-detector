FROM golang:1.24 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

RUN go build -o copy-detector ./cmd/copy-detector

FROM gcr.io/distroless/base-debian12

WORKDIR /app

COPY --from=builder /app/copy-detector .

ENTRYPOINT ["./copy-detector"]

# перересоваывается терминал
# выбор интеерфейса
#в таблице не только ip но и порт