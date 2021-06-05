# Parameters
GOCMD=go
GO_VERSION=1.16.4
BINARY_DEST_SUB_DIR=bin
BINARY_NAME=check_wireguard

all: build

clean:
	$(GOCLEAN)
	rm -rf bin
	rm -rf ui/node_modules ui/dist
	rm -rf bindatas

binary:
	$(GOCMD) build -o $(BINARY_DEST_SUB_DIR)/$(BINARY_NAME) .

build: binary

create_container_image:
	echo podman build -f docker/check-wireguard.Dockerfile --target=check_wireguard -t check_wireguard .

build_container:
	podman build -f docker/check-wireguard.Dockerfile --target=build_check_wireguard -t build_check_wireguard .

container: build_container create_container_image

test:
	$(BINARY_DEST_SUB_DIR)/$(BINARY_NAME) --help
