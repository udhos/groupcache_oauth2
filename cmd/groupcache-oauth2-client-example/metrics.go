package main

import (
	"log"

	"github.com/modernprogram/groupcache/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/udhos/groupcache_exporter"
	"github.com/udhos/groupcache_exporter/groupcache/modernprogram"
)

// metrics is used only to make sure client.MetricsExporter conforms with groupcache_exporter.NewExporter.
func metrics(workspace *groupcache.Workspace) {
	//
	// expose prometheus metrics
	//
	metricsRoute := "/metrics"
	metricsPort := ":3000"

	log.Printf("starting metrics server at: %s %s", metricsPort, metricsRoute)

	labels := map[string]string{
		//"app": "app1",
	}
	namespace := ""
	listGroups := func() []groupcache_exporter.GroupStatistics {
		return modernprogram.ListGroups(workspace)
	}
	options := groupcache_exporter.Options{
		Namespace:  namespace,
		Labels:     labels,
		ListGroups: listGroups,
	}
	collector := groupcache_exporter.NewExporter(options)
	prometheus.MustRegister(collector)

	/*
		go func() {
			http.Handle(metricsRoute, promhttp.Handler())
			log.Fatal(http.ListenAndServe(metricsPort, nil))
		}()
	*/
}
