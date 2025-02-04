package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	reportPath   = "/tmp/report.json"
	scanInterval = 24 * time.Hour // Définition explicite de l'intervalle
)

// Structure pour les métriques Prometheus
var (
	severityMetrics = map[string]prometheus.Gauge{
		"CRITICAL": promauto.NewGauge(prometheus.GaugeOpts{
			Name: "trivy_vulnerabilities_critical",
			Help: "Number of critical vulnerabilities",
		}),
		"HIGH": promauto.NewGauge(prometheus.GaugeOpts{
			Name: "trivy_vulnerabilities_high",
			Help: "Number of high vulnerabilities",
		}),
		"MEDIUM": promauto.NewGauge(prometheus.GaugeOpts{
			Name: "trivy_vulnerabilities_medium",
			Help: "Number of medium vulnerabilities",
		}),
		"LOW": promauto.NewGauge(prometheus.GaugeOpts{
			Name: "trivy_vulnerabilities_low",
			Help: "Number of low vulnerabilities",
		}),
		"UNKNOWN": promauto.NewGauge(prometheus.GaugeOpts{
			Name: "trivy_vulnerabilities_unknown",
			Help: "Number of unknown vulnerabilities",
		}),
	}
	lastScanTime = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "trivy_last_scan_timestamp",
		Help: "Timestamp of the last successful Trivy scan",
	})
)

// Structure pour parser le rapport JSON de Trivy
type TrivyReport struct {
	Results []struct {
		Vulnerabilities []struct {
			Severity string `json:"Severity"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

func runTrivyScan() error {
	log.Printf("Starting Trivy scan at %s", time.Now().Format(time.RFC3339))
	cmd := exec.Command("trivy", "fs", "/", "--format", "json", "--output", reportPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("trivy scan failed: %v\noutput: %s", err, output)
	}
	log.Printf("Trivy scan completed successfully. Report saved to %s", reportPath)
	lastScanTime.Set(float64(time.Now().Unix()))
	return nil
}

func parseTrivyReport() error {
	if _, err := os.Stat(reportPath); os.IsNotExist(err) {
		return fmt.Errorf("report file %s does not exist", reportPath)
	}

	data, err := ioutil.ReadFile(reportPath)
	if err != nil {
		return fmt.Errorf("error reading report file: %v", err)
	}

	var report TrivyReport
	if err := json.Unmarshal(data, &report); err != nil {
		return fmt.Errorf("error parsing JSON: %v", err)
	}

	for _, metric := range severityMetrics {
		metric.Set(0)
	}

	for _, result := range report.Results {
		for _, vuln := range result.Vulnerabilities {
			severity := strings.ToUpper(vuln.Severity)
			if metric, ok := severityMetrics[severity]; ok {
				metric.Inc()
			}
		}
	}

	return nil
}

func main() {
	http.Handle("/metrics", promhttp.Handler())

	go func() {
		log.Printf("Starting Prometheus metrics server on :9393")
		if err := http.ListenAndServe(":9393", nil); err != nil {
			log.Fatal(err)
		}
	}()

	log.Printf("Starting initial Trivy scan...")
	if err := runTrivyScan(); err != nil {
		log.Printf("Error running initial Trivy scan: %v", err)
	}
	if err := parseTrivyReport(); err != nil {
		log.Printf("Error parsing initial Trivy report: %v", err)
	}

	nextScan := time.Now().Add(scanInterval)
	log.Printf("Initial scan completed. Next scan scheduled for: %s", nextScan.Format(time.RFC3339))

	for {
		time.Sleep(scanInterval)
		if err := runTrivyScan(); err != nil {
			log.Printf("Error running scheduled Trivy scan: %v", err)
			continue
		}
		if err := parseTrivyReport(); err != nil {
			log.Printf("Error parsing Trivy report: %v", err)
			continue
		}
		nextScan = time.Now().Add(scanInterval)
		log.Printf("Scan completed. Next scan scheduled for: %s", nextScan.Format(time.RFC3339))
	}
}
