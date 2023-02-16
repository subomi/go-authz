package goauthz

import "github.com/prometheus/client_golang/prometheus"

// Namespace used in fully-qualified metrics names.
const namespace = "goauthz"

// Define metrics.
type metrics struct {
	authorizationRequestsHistogram prometheus.HistogramVec
}

func NewMetrics(reg prometheus.Registerer) *metrics {
	m := &metrics{
		authorizationRequestsHistogram: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "authorization_request",
			Help:      "All authorization request observations",
		}, []string{"policy", "rule"}),
	}

	reg.MustRegister(m.authorizationRequestsHistogram)

	return m
}
