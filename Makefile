.PHONY: build
build: clean install
	pnpm run build

.PHONY: lint
lint:
	pnpm run lint

.PHONY: typecheck
typecheck:
	pnpm run typecheck

.PHONY: test
test:
	pnpm run test

.PHONY: audit
audit:
	pnpm run audit

.PHONY: install
install:
	pnpm install

.PHONY: clean
clean:
	pnpm -r exec rm -rf dist
