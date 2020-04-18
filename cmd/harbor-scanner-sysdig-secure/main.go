package main

import (
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/http/api"
	v1 "github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/http/api/v1"
	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/scanner"
	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/secure"
)

func main() {
	log.SetOutput(os.Stdout)
	log.SetLevel(log.TraceLevel)

	log.Info("Starting harbor-scanner-sysdig-secure")

	apiHandler := v1.NewAPIHandler(
		scanner.NewBackendAdapter(
			secure.NewClient(os.Getenv("SECURE_API_TOKEN"), os.Getenv("SECURE_URL"))),
		log.StandardLogger().Writer())

	apiServer := api.NewServer(apiHandler)

	log.Fatal(apiServer.ListenAndServe())
}
