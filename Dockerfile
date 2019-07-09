FROM golang:alpine as builder
WORKDIR /opt/build
RUN apk add --no-cache git ca-certificates tzdata && update-ca-certificates
COPY . .
RUN go mod download
RUN GOOS=linux GOARCH=amd64 VERSION=`git describe --tags --abbrev=0` go build -ldflags "-X main.Version=$VERSION -w -s" -o gangway

FROM alpine
RUN apk add --no-cache ca-certificates tzdata && update-ca-certificates
COPY --from=builder /opt/build/gangway /gangway
COPY --from=builder /opt/build/public /public
ENTRYPOINT ["/gangway"]