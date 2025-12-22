IMAGE_NAME := vulnmng:latest

.PHONY: build test scan e2e

build:
	docker build -t $(IMAGE_NAME) .

test:
	# Run unit tests (if any)
	python -m unittest discover vulnmng

scan:
	# Example scan usage
	docker run --rm -v $(PWD):/scan_target $(IMAGE_NAME) python -m vulnmng.cli scan /scan_target --report-md /scan_target/report.md

scan-self: build
	# Scan the built image itself
	docker run --rm -v $(PWD):/app/output $(IMAGE_NAME) python -m vulnmng.cli scan "registry:$(IMAGE_NAME)" --report-md /app/output/report-self.md

report:
	# Generate report from issues.json
	# Usage: make report JSON_PATH=path/to/issues.json TARGET=optional-target
	python -m vulnmng.cli report --json-path $(or $(JSON_PATH), issues.json) $(if $(TARGET),--target $(TARGET),) --format-md report.md --format-csv report.csv

e2e: build
	./scripts/e2e_test.sh
