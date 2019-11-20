package metrics

import (
	"fmt"
	"net/http"

	"github.com/ethereum/go-ethereum/log"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Server runs and controls a HTTP pprof interface.
type Server struct {
	server *http.Server
}

func NewMetricsServer(port int) *Server {
	mux := http.NewServeMux()
	mux.Handle("/health", healthHandler())
	mux.Handle("/metrics", Handler())
	p := Server{
		server: &http.Server{
			Addr:    fmt.Sprintf(":%d", port),
			Handler: mux,
		},
	}
	return &p
}

func healthHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte("OK"))
		if err != nil {
			log.Error("health handler error", "err", err)
		}
	})
}

func Handler() http.Handler {
	statusMetrics := promhttp.Handler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		statusMetrics.ServeHTTP(w, r)
	})
}

// Listen starts the HTTP server in the background.
func (p *Server) Listen() {
	log.Info("metrics server stopped", "err", p.server.ListenAndServe())
}
