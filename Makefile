SHELL := /bin/bash
VENV  := .venv
PY    := $(VENV)/bin/python
PIP   := $(VENV)/bin/pip
HAS_DOCKER := $(shell command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 && echo yes || echo no)

.PHONY: bootstrap lint test tf-fmt tf-validate tf-test policy-test ansible-lint molecule scan arm-check ci clean

bootstrap: $(VENV)/bin/activate
$(VENV)/bin/activate:
	python3 -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -e "./platformctl[dev]" -e "./app[dev]" pre-commit ansible ansible-lint "molecule>=6" "molecule-plugins[docker]"
	$(VENV)/bin/pre-commit install

lint: bootstrap
	$(VENV)/bin/ruff check .
	$(VENV)/bin/ruff format --check .
	$(VENV)/bin/mypy

test: bootstrap
	$(VENV)/bin/pytest --cov --cov-report=term-missing

tf-fmt:
	terraform fmt -check -recursive infra/terraform

tf-validate:
	@for d in infra/terraform/modules/*/* infra/terraform/stacks/*; do \
	  echo "== $$d"; (cd $$d && terraform init -backend=false -input=false >/dev/null && terraform validate) || exit 1; \
	done

tf-test:
	@for d in infra/terraform/modules/*/*; do \
	  echo "== $$d"; (cd $$d && terraform init -backend=false -input=false >/dev/null && terraform test) || exit 1; \
	done

policy-test:
	conftest verify -p policy/terraform
	conftest fmt --check policy/terraform

ansible-lint: bootstrap
	cd ansible && ../$(VENV)/bin/ansible-lint

molecule: bootstrap
ifeq ($(HAS_DOCKER),yes)
	cd ansible && ../$(VENV)/bin/molecule test
else
	@echo "SKIP: molecule (docker not available)"
endif

scan: bootstrap
	$(VENV)/bin/platformctl scan --fail-on high

arm-check:
	$(PY) -c "import json,sys; json.load(open('infra/arm/keyvault.json')); json.load(open('infra/arm/keyvault.parameters.json')); print('ARM JSON ok')"

ci: lint test tf-fmt tf-validate tf-test policy-test ansible-lint molecule arm-check scan
	@echo "CI (local subset) passed"

clean:
	rm -rf $(VENV) .platformctl .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage
	find . -name '.terraform' -type d -prune -exec rm -rf {} + 2>/dev/null || true
	find . -name '.terragrunt-cache' -type d -prune -exec rm -rf {} + 2>/dev/null || true
