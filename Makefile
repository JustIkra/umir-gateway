.PHONY: tools fmt fmt-all fmt-check build lint arch test integration check quality-test
tools:
	bash scripts/install-go-quality.sh
fmt:
	bash scripts/go-quality.sh fmt $(FILES)
fmt-all:
	bash scripts/go-quality.sh fmt-all
fmt-check build lint arch test integration check:
	bash scripts/go-quality.sh $@
quality-test:
	bash tests/quality/check.sh

.PHONY: sync-contract
FACTORY_API ?= ../factory/docs/api
sync-contract:
	node scripts/sync-auth-contract.mjs $(FACTORY_API)/registration-v1-composed-public.json $(FACTORY_API)/registration-v1-composed-private.json internal/operatorhttp/auth-contract.json
	node scripts/sync-scoped-contract.mjs $(FACTORY_API)/registration-v1-composed-public.json internal/httpapi/scoped-contract.json
