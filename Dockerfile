FROM golang:1.27.0 AS builder

WORKDIR /app

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o webhook ./cmd/cert-manager-lego-webhook

FROM gcr.io/distroless/static:nonroot
COPY --from=builder --chown=nonroot:nonroot /app/webhook /webhook

USER nonroot

ENTRYPOINT ["/webhook"]
