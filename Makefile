test:
	ginkgo -r .

docker:
	docker build -f build/Dockerfile -t sysdiglabs/harbor-scanner-sysdig-secure .
