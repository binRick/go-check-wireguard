FROM alpine:latest as build_check_wireguard
ARG GO_VERSION=1.16.4

RUN apk update
RUN apk upgrade
RUN apk add git tcpdump ngrep bash zsh rsync sqlite dnsmasq nftables iperf curl wget tmux file gcompat \
            librrd strace openssh npm gcc automake make

WORKDIR /usr/src
COPY docker/files/go1.16.4.linux-amd64.tar.gz /usr/src/go1.16.4.linux-amd64.tar.gz
RUN ls -altr /usr/src && \
    file  /usr/src/go1.16.4.linux-amd64.tar.gz && \
    tar zxf go1.16.4.linux-amd64.tar.gz && mv go /opt && \
    ln -sf /opt/go/bin/go /usr/bin/go && \
    ln -sf /opt/go/bin/gofmt /usr/bin/gofmt  && \
    command -v go && \
    go version


WORKDIR /go-check-wireguard
COPY ./*.go ./go.mod ./go.sum /go-check-wireguard/.
COPY ./Makefile /go-check-wireguard/.

COPY ./types/ /go-check-wireguard/types/.
COPY ./cmd/ /go-check-wireguard/cmd/.

RUN make

RUN make test




FROM alpine:latest as check_wireguard

COPY --from=build_check_wireguard /go-check-wireguard/bin/check-wireguard /usr/bin/check-wireguard

RUN /usr/bin/check-wireguard --help

CMD ["/usr/bin/check-wireguard"]
