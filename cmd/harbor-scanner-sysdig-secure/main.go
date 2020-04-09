package main

import (
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/http/api"
	v1 "github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/http/api/v1"
)

func main() {
	log.SetOutput(os.Stdout)
	log.SetLevel(log.TraceLevel)

	log.Info("Starting harbor-scanner-sysdig-secure")

	apiHandler := v1.NewAPIHandler()
	apiServer := api.NewServer(apiHandler)

	log.Fatal(apiServer.ListenAndServe())
}
