package v1

import (
	"net/http"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

const (
	scannerAdapterMetadataMimeType = "application/vnd.scanner.adapter.metadata+json; version=1.0"
)

func NewAPIHandler() http.Handler {
	router := mux.NewRouter()

	router.Use(logRequest)

	apiV1Router := router.PathPrefix("/api/v1").Subrouter()

	apiV1Router.Methods(http.MethodGet).Path("/metadata").HandlerFunc(metadata)

	return router
}

func logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Tracef("%s - %s %s %s", r.RemoteAddr, r.Proto, r.Method, r.URL.RequestURI())
		next.ServeHTTP(w, r)
	})
}

func metadata(res http.ResponseWriter, req *http.Request) {
	res.Header().Set("Content-Type", scannerAdapterMetadataMimeType)
}
