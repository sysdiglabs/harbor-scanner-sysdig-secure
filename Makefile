test:
	ginkgo -r . --randomizeAllSpecs --randomizeSuites --failOnPending --trace --race --progress

docker:
	docker build -f build/Dockerfile -t sysdiglabs/harbor-scanner-sysdig-secure .
	docker push sysdiglabs/harbor-scanner-sysdig-secure
