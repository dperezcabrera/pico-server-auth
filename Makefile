VERSIONS = 3.11 3.12 3.13 3.14

build-%:
	docker build --build-arg PYTHON_VERSION=$* -t pico-server-auth-test:$* -f Dockerfile.test .

test-%: build-%
	docker run --rm pico-server-auth-test:$*

test-all: $(addprefix test-,$(VERSIONS))

.PHONY: build-% test-% test-all
