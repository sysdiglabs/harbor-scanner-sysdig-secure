test:
	ginkgo -randomizeAllSpecs -randomizeSuites -failOnPending -trace -race -progress -cover -r

docker:
	docker build -f build/Dockerfile -t sysdiglabs/harbor-scanner-sysdig-secure .
	docker push sysdiglabs/harbor-scanner-sysdig-secure
