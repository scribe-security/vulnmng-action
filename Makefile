IMAGE_NAME := vulnmng:latest
GHCR_IMAGE := ghcr.io/scribe-security/vulnmng:latest
PYTHON := python3

.PHONY: build test scan e2e test-published scan-published e2e-published

build:
	docker build -t $(IMAGE_NAME) .

test:
	# Run unit tests locally
	$(PYTHON) -m unittest discover tests -v

test-published:
	# Pull and test using the published GHCR image
	docker pull $(GHCR_IMAGE)
	docker run --rm -v $(PWD):/workspace -w /workspace $(GHCR_IMAGE) -m unittest discover tests -v

scan:
	# Example scan usage
	docker run --rm -v $(PWD):/scan_target $(IMAGE_NAME) scan /scan_target --report-md /scan_target/report.md

scan-published:
	# Scan using the published GHCR image
	docker pull $(GHCR_IMAGE)
	docker run --rm -v $(PWD):/scan_target $(GHCR_IMAGE) scan /scan_target --json-path /scan_target/issues.json

scan-self: build
	# Scan the built image itself
	docker run --rm -v $(PWD):/app/output $(IMAGE_NAME) scan "registry:$(IMAGE_NAME)" --report-md /app/output/report-self.md

report:
	# Generate report from issues.json
	# Usage: make report JSON_PATH=path/to/issues.json TARGET=optional-target
	$(PYTHON) -m vulnmng.cli report --json-path $(or $(JSON_PATH), issues.json) $(if $(TARGET),--target $(TARGET),) --format-md report.md --format-csv report.csv

e2e: build
	./scripts/e2e_test.sh

e2e-published:
	# Run E2E tests using published GHCR image
	docker pull $(GHCR_IMAGE)
	IMAGE_NAME=$(GHCR_IMAGE) ./scripts/e2e_test.sh
