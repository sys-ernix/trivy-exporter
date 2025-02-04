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
	reportPath = "/tmp/report.json"
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
	cmd := exec.Command("trivy", "fs", "/", "--format", "json", "--output", reportPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("trivy scan failed: %v\noutput: %s", err, output)
	}
	log.Printf("Trivy scan completed successfully. Report saved to %s", reportPath)
	return nil
}

func parseTrivyReport() error {
	// Vérifier si le fichier existe
	if _, err := os.Stat(reportPath); os.IsNotExist(err) {
		return fmt.Errorf("report file %s does not exist", reportPath)
	}

	// Lire le fichier
	data, err := ioutil.ReadFile(reportPath)
	if err != nil {
		return fmt.Errorf("error reading report file: %v", err)
	}

	// Parser le JSON
	var report TrivyReport
	if err := json.Unmarshal(data, &report); err != nil {
		return fmt.Errorf("error parsing JSON: %v", err)
	}

	// Réinitialiser toutes les métriques
	for _, metric := range severityMetrics {
		metric.Set(0)
	}

	// Compter les vulnérabilités par sévérité
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
	// Configurer le endpoint Prometheus
	http.Handle("/metrics", promhttp.Handler())

	// Démarrer le serveur HTTP dans une goroutine
	go func() {
		log.Printf("Starting Prometheus metrics server on :9393")
		if err := http.ListenAndServe(":9393", nil); err != nil {
			log.Fatal(err)
		}
	}()

	// Créer un ticker qui s'exécute toutes les 24 heures
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	// Première exécution immédiate
	log.Printf("Starting initial Trivy scan...")
	if err := runTrivyScan(); err != nil {
		log.Printf("Error running initial Trivy scan: %v", err)
	}
	if err := parseTrivyReport(); err != nil {
		log.Printf("Error parsing initial Trivy report: %v", err)
	}
	log.Printf("Initial scan completed. Next scan will be in 24 hours")

	// Boucle principale utilisant le ticker
	for range ticker.C {
		log.Printf("Starting scheduled Trivy scan...")
		if err := runTrivyScan(); err != nil {
			log.Printf("Error running Trivy scan: %v", err)
		}

		if err := parseTrivyReport(); err != nil {
			log.Printf("Error parsing Trivy report: %v", err)
		}
		log.Printf("Scan completed. Next scan will be in 24 hours")
	}
}
