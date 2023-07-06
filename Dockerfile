FROM golang:1.20 AS builder

WORKDIR /app

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GO11MODULE=on go build -o webhook .

FROM gcr.io/distroless/static:nonroot
COPY --from=builder --chown=nonroot:nonroot /app/webhook /webhook

USER nonroot

ENTRYPOINT ["/webhook"]
