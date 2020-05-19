package main

import (
	"os"

	log "github.com/sirupsen/logrus"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/http/api"
	v1 "github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/http/api/v1"
	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/scanner"
	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/secure"
)

func main() {
	log.SetOutput(os.Stdout)
	log.SetLevel(log.TraceLevel)
	log.Info("Starting harbor-scanner-sysdig-secure")

	apiHandler := v1.NewAPIHandler(getAdapter(), log.StandardLogger().Writer())

	apiServer := api.NewServer(apiHandler)

	log.Fatal(apiServer.ListenAndServe())
}

func getAdapter() scanner.Adapter {
	client := secure.NewClient(os.Getenv("SECURE_API_TOKEN"), os.Getenv("SECURE_URL"))

	if _, ok := os.LookupEnv("INLINE_SCANNING"); ok {
		log.Info("Using inline-scanning adapter")
		config, err := rest.InClusterConfig()
		if err != nil {
			log.Fatal(err)
		}

		clientset, err := kubernetes.NewForConfig(config)
		if err != nil {
			log.Fatal(err)
		}
		return scanner.NewInlineAdapter(client, clientset, "harbor-scanner-sysdig-secure")
	}

	log.Info("Using backend-scanning adapter")
	return scanner.NewBackendAdapter(client)
}
