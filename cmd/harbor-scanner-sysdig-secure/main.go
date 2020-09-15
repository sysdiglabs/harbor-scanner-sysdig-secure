package main

import (
	"errors"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/http/api"
	v1 "github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/http/api/v1"
	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/scanner"
	"github.com/sysdiglabs/harbor-scanner-sysdig-secure/pkg/secure"
)

func main() {
	if err := configure(); err != nil {
		fmt.Printf("%s \n\n", err)

		pflag.Usage()
		os.Exit(1)
	}

	log.SetOutput(os.Stdout)
	log.SetLevel(log.TraceLevel)
	log.Info("Starting harbor-scanner-sysdig-secure")

	apiHandler := v1.NewAPIHandler(getAdapter(), log.StandardLogger().Writer())

	apiServer := api.NewServer(apiHandler)

	log.Fatal(apiServer.ListenAndServe())
}

func configure() error {
	viper.AutomaticEnv()

	pflag.String("secure_api_token", "", "Sysdig Secure API Token")
	pflag.String("secure_url", "https://secure.sysdig.com", "Sysdig Secure URL Endpoint")
	pflag.Bool("verify_ssl", true, "Verify SSL when connecting to Sysdig Secure URL Endpoint")
	pflag.Bool("inline_scanning", false, "Use Inline Scanning Adapter")
	pflag.String("namespace_name", "", "Namespace where inline scanning jobs are spawned")
	pflag.String("configmap_name", "", "Configmap which keeps the inline scanning settings")
	pflag.String("secret_name", "", "Secret which keeps the inline scanning secrets ")

	pflag.VisitAll(func(flag *pflag.Flag) { viper.BindPFlag(flag.Name, flag) })

	pflag.Parse()

	if viper.Get("secure_api_token") == "" {
		return errors.New("secure_api_token is required")
	}

	if viper.GetBool("inline_scanning") && (viper.Get("namespace_name") == "" || viper.Get("configmap_name") == "" || viper.Get("secret_name") == "") {
		return errors.New("namespace_name, configmap_name and secret_name are required when running inline scanning")
	}

	return nil
}

func getAdapter() scanner.Adapter {
	client := secure.NewClient(viper.GetString("secure_api_token"), viper.GetString("secure_url"), viper.GetBool("verify_ssl"))

	if viper.GetBool("inline_scanning") {
		log.Info("Using inline-scanning adapter")
		config, err := rest.InClusterConfig()
		if err != nil {
			log.Fatal(err)
		}

		clientset, err := kubernetes.NewForConfig(config)
		if err != nil {
			log.Fatal(err)
		}
		return scanner.NewInlineAdapter(
			client,
			clientset,
			viper.GetString("secure_url"),
			viper.GetString("namespace_name"),
			viper.GetString("configmap_name"),
			viper.GetString("secret_name"))
	}

	log.Info("Using backend-scanning adapter")
	return scanner.NewBackendAdapter(client)
}
