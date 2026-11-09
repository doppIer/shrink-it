.PHONY: up down logs test lint demo

up: ## build and start the stack
	@test -f .env || cp .env.example .env
	docker compose up -d --build

down:
	docker compose down

logs:
	docker compose logs -f app

test:
	go test -race ./...

lint:
	go vet ./...
	@test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)

demo: ## create a sample smart link and show where different visitors land
	./scripts/demo.sh
