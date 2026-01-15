FROM golang:1.25-alpine

RUN apk add --no-cache make git curl build-base tar bash

RUN git clone https://github.com/go-delve/delve.git /go/src/github.com/go-delve/delve
WORKDIR /go/src/github.com/go-delve/delve

RUN make install

RUN go get golang.org/x/tools/cmd/godoc
