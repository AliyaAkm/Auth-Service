FROM golang:1.23 as Builder

WORKDIR /ZerdeStudy

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o main ./cmd

FROM alpine:3.20

WORKDIR /ZerdeStudy

COPY --from=Builder /ZerdeStudy/main .

CMD ["./main"]

