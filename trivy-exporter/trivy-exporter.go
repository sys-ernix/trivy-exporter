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
    baseDir = "/opt/trivy-exporter"
    reportPath = baseDir + "/report.json"
    logPath = "/var/log/trivy-exporter.log"
)

// Structure détaillée pour les vulnérabilités
type TrivyReport struct {
    Results []struct {
        Target string `json:"Target"`
        Vulnerabilities []struct {
            VulnerabilityID  string `json:"VulnerabilityID"`
            PkgName         string `json:"PkgName"`
            InstalledVersion string `json:"InstalledVersion"`
            FixedVersion    string `json:"FixedVersion"`
            Severity        string `json:"Severity"`
            Description     string `json:"Description"`
            Title          string `json:"Title"`
        } `json:"Vulnerabilities"`
    } `json:"Results"`
}

var (
    // Métriques de base par sévérité
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

    // Nouvelle métrique pour les détails des CVEs
    vulnDetails = promauto.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "trivy_vulnerability",
            Help: "Detailed information about each vulnerability",
        },
        []string{
            "vulnerability_id",
            "severity",
            "package_name",
            "installed_version",
            "fixed_version",
            "title",
            "target",
        },
    )

    // Timestamp du dernier scan
    lastScanTime = promauto.NewGauge(prometheus.GaugeOpts{
        Name: "trivy_last_scan_timestamp",
        Help: "Timestamp of the last successful Trivy scan",
    })
)

func runTrivyScan() error {
    startTime := time.Now()
    log.Printf("=== [%s] STARTING TRIVY SCAN ===", startTime.Format(time.RFC3339))
    
    cmd := exec.Command("trivy", "fs", "/", "--format", "json", "--scanners", "vuln", "--output", reportPath)
    output, err := cmd.CombinedOutput()
    
    endTime := time.Now()
    log.Printf("=== [%s] SCAN FINISHED (Duration: %v) ===", 
        endTime.Format(time.RFC3339), 
        endTime.Sub(startTime))
        
    if err != nil {
        return fmt.Errorf("trivy scan failed: %v\noutput: %s", err, output)
    }
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

    // Reset toutes les métriques
    for _, metric := range severityMetrics {
        metric.Set(0)
    }
    vulnDetails.Reset()

    // Mise à jour des métriques
    for _, result := range report.Results {
        for _, vuln := range result.Vulnerabilities {
            // Incrémenter le compteur de sévérité
            severity := strings.ToUpper(vuln.Severity)
            if metric, ok := severityMetrics[severity]; ok {
                metric.Inc()
            }

            // Ajouter les détails de la vulnérabilité
            vulnDetails.With(prometheus.Labels{
                "vulnerability_id":   vuln.VulnerabilityID,
                "severity":          vuln.Severity,
                "package_name":      vuln.PkgName,
                "installed_version": vuln.InstalledVersion,
                "fixed_version":     vuln.FixedVersion,
                "title":            vuln.Title,
                "target":           result.Target,
            }).Set(1)
        }
    }

    return nil
}

func init() {
    if err := os.MkdirAll(baseDir, 0755); err != nil {
        log.Fatal(err)
    }
    logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
    if err != nil {
        log.Fatal(err)
    }
    log.SetOutput(logFile)
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

    nextScan := time.Now().Add(24 * time.Hour)
    log.Printf("Initial scan completed. Next scan scheduled for: %s", nextScan.Format(time.RFC3339))

    for {
        time.Sleep(24 * time.Hour)
        if err := runTrivyScan(); err != nil {
            log.Printf("Error running scheduled Trivy scan: %v", err)
            continue
        }
        if err := parseTrivyReport(); err != nil {
            log.Printf("Error parsing Trivy report: %v", err)
            continue
        }
        nextScan = time.Now().Add(24 * time.Hour)
        log.Printf("Scan completed. Next scan scheduled for: %s", nextScan.Format(time.RFC3339))
    }
}