package main

import (
	"log"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/udhos/groupcache_exporter"
	"github.com/udhos/groupcache_oauth2/clientcredentials"
)

// metrics is used only to make sure client.MetricsExporter conforms with groupcache_exporter.NewExporter.
func metrics(client *clientcredentials.Client) {
	//
	// expose prometheus metrics
	//
	metricsRoute := "/metrics"
	metricsPort := ":3000"

	log.Printf("starting metrics server at: %s %s", metricsPort, metricsRoute)

	//exporter := modernprogram.New(cache)
	exporter := client.MetricsExporter()
	labels := map[string]string{
		//"app": "app1",
	}
	namespace := ""
	collector := groupcache_exporter.NewExporter(namespace, labels, exporter)
	prometheus.MustRegister(collector)

	/*
		go func() {
			http.Handle(metricsRoute, promhttp.Handler())
			log.Fatal(http.ListenAndServe(metricsPort, nil))
		}()
	*/
}
