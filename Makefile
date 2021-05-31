# Parameters
GOCMD=go
COPYCMD=cp
GO_VERSION=1.16.4
REAP=reap -vx
PASSH=passh
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOGET=$(GOCMD) get
COPY=$(COPYCMD)
BINARY_NAME=dns_proxy_server
BINARY_DEST_SUB_DIR=bin
DEV_CMD=make kill && $(REAP) make test
BINARY_PATH=$(BINARY_DEST_SUB_DIR)/$(BINARY_NAME)
RUN_PORT=8384
DOMAINS=google.com


all: build

clean:
	$(GOCLEAN)
	rm -rf $(BINARY_DEST_SUB_DIR)/$(BINARY_NAME)

build: binary

binary:
	mkdir -p $(BINARY_DEST_SUB_DIR)
	$(GOBUILD) -o $(BINARY_DEST_SUB_DIR)/$(BINARY_NAME) -v

binary-cgo:
	CGO_ENABLED=1 $(GOBUILD) -o $(BINARY_DEST_SUB_DIR)/$(CGO_BINARY_NAME) -v

binary-no-cgo:
	CGO_ENABLED=0 $(GOBUILD) -o $(BINARY_DEST_SUB_DIR)/$(NO_CGO_BINARY_NAME) -v

help:
	eval $(BINARY_PATH) --help

kill:
	pidof $(BINARY_NAME) && { killall -9 $(BINARY_NAME); } || { true; } 

dev:
	command nodemon -i bin -w ../dns_proxy/ -w Makefile -w . -V --delay .1 -e go,sum -x sh -- -c "$(DEV_CMD)||true"
