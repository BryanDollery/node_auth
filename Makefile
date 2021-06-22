run: stop start logs

dev:
	npm install
	docker build --tag bryandollery/$$(basename $$PWD) -f Dockerfile-dev .

build: 
	docker build --tag bryandollery/$$(basename $$PWD) .

PORT := 80
EXPOSED_PORT := 9000

start:
	docker container run -it -d \
		   -e EXPOSED_PORT=$(EXPOSED_PORT) \
		   -e PORT=$(PORT) \
		   -p $(EXPOSED_PORT):$(PORT) \
		   -v /var/run/docker.sock:/var/run/docker.sock \
		   -v "$$PWD":/"$$(basename $$PWD)" \
		   -w "/$$(basename $$PWD)" \
		   --hostname "$$(basename $$PWD)" \
		   --name "$$(basename $$PWD)" \
		   bryandollery/$$(basename $$PWD)

exec:
	docker exec -it "$$(basename $$PWD)" bash || true

stop:
	docker rm -f "$$(basename $$PWD)" 2> /dev/null || true

logs:
	docker logs -f "$$(basename $$PWD)" | pino-pretty -c -l -i pid,hostname
