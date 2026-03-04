package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

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
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})))

	if err := configure(); err != nil {
		slog.Error("configuration error", "error", err)
		fmt.Println()
		pflag.Usage()
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	slog.Info("starting harbor-scanner-sysdig-secure")

	adapter := getAdapter()
	if viper.GetBool("async_mode") {
		slog.Info("async mode enabled")
		adapter = scanner.NewAsyncAdapter(ctx, adapter, scanner.DefaultAsyncAdapterRefreshRate)
	}

	apiHandler := v1.NewAPIHandler(adapter)
	apiServer := api.NewServer(apiHandler)

	if err := apiServer.ListenAndServe(); err != nil {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
}

func configure() error {
	viper.AutomaticEnv()

	pflag.String("secure_api_token", "", "Sysdig Secure API Token")
	pflag.String("secure_url", "https://secure.sysdig.com", "Sysdig Secure URL Endpoint")
	pflag.Bool("verify_ssl", true, "Verify SSL when connecting to Sysdig Secure URL Endpoint")
	pflag.Bool("cli_scanning", false, "Use Sysdig-Cli-Scanner Scanning Adapter")
	pflag.Bool("async_mode", false, "Use Async-Mode to perform reports retrieval")
	pflag.String("namespace_name", "", "Namespace where inline scanning jobs are spawned")
	pflag.String("secret_name", "", "Secret which keeps the inline scanning secrets ")
	pflag.String("cli_scanning_extra_params", "", "Extra parameters to provide to cli-scanner")
	pflag.String("cli_scanner_image", "", "Extra parameters to provide to cli-scanner")

	pflag.VisitAll(func(flag *pflag.Flag) { _ = viper.BindPFlag(flag.Name, flag) })

	pflag.Parse()

	if viper.Get("secure_api_token") == "" {
		return errors.New("secure_api_token is required")
	}

	if viper.GetBool("cli_scanning") && (viper.Get("namespace_name") == "" || viper.Get("secret_name") == "") {
		return errors.New("namespace_name and secret_name are required when running sysdig-cli-scanner")
	}

	return nil
}

func getAdapter() scanner.Adapter {
	client := secure.NewClient(viper.GetString("secure_api_token"), viper.GetString("secure_url"), viper.GetBool("verify_ssl"))

	if viper.GetBool("cli_scanning") {
		slog.Info("using cli-scanner adapter")
		config, err := rest.InClusterConfig()
		if err != nil {
			slog.Error("failed to get in-cluster config", "error", err)
			os.Exit(1)
		}

		clientset, err := kubernetes.NewForConfig(config)
		if err != nil {
			slog.Error("failed to create kubernetes client", "error", err)
			os.Exit(1)
		}

		return scanner.NewInlineAdapter(
			client,
			clientset,
			viper.GetString("secure_url"),
			viper.GetString("namespace_name"),
			viper.GetString("secret_name"),
			viper.GetString("cli_scanning_extra_params"),
			viper.GetBool("verify_ssl"))
	}

	slog.Error("please specify the cli-scanner (--cli_scanning) command line parameter, backend scanning no longer supported")
	os.Exit(1)
	return nil
}
