package main

import "github.com/prometheus/client_golang/prometheus"

// Relay-specific metrics for the SMTP relay. Registered into the shared
// jmapserver metrics registry via RegisterMetrics(..., relayCollectors()...).
var (
	smtpOutbound = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "biset_smtp_outbound_total",
		Help: "Outbound SMTP send attempts, by result.",
	}, []string{"result"})
)

// relayCollectors returns the SMTP-specific collectors and pre-initializes
// known label series to 0 so they are present before the first event.
func relayCollectors() []prometheus.Collector {
	smtpOutbound.WithLabelValues("sent")
	smtpOutbound.WithLabelValues("failed")
	return []prometheus.Collector{smtpOutbound}
}
