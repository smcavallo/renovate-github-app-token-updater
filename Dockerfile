FROM golang:1.23 as builder

WORKDIR /opt/

COPY go.mod go.sum ./
RUN go mod download

COPY ./pkg /opt/pkg

ENV GOOS linux
ENV CGO_ENABLED=0

ARG VERSION
RUN find /opt/

# RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -ldflags="-w -s" -o /go/bin/hello
RUN go build -v -o github-app-token-updater /opt/pkg/app

FROM gcr.io/distroless/base
COPY --from=builder /opt/github-app-token-updater /usr/local/bin/github-app-token-updater
ENTRYPOINT ["/usr/local/bin/github-app-token-updater"]
