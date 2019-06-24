FROM golang:alpine as builder
WORKDIR /opt/build
RUN adduser -D -g '' appuser
RUN apk add --no-cache git ca-certificates tzdata && update-ca-certificates
COPY . .
RUN go mod download
RUN GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o gangway

FROM alpine
RUN apk add --no-cache ca-certificates tzdata && update-ca-certificates
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /opt/build/gangway /gangway
USER appuser
ENTRYPOINT ["/gangway"]