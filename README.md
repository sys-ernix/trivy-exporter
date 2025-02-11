# trivy-exporter

Ceci est projet pour créer un exporter Prometheus pour Trivy afin d'avoir des métriques temporels pouvoir l'intégrer dans un dashboard Grafana.

Dans ce dossier, il y a deux parties. La partie de l'exporter en code source golang et la partie ansible pour le déploiement

## trivy Exporter

>![Warning] Je précise que ce projet est fait pour exporter le résultat d'un scan trivy pour les CVEs. Ça a été créé uniquement dans ce besoin précis et pour me familiariser avec le langage Golang.

Les dépendances supplémentaire suivante son nécessaire pour la compilation

```golang
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
```

## Ansible

La partie ansible est présente pour faciliter le déploiement de l'exporter. La première partie du playbook

```yaml
- name: Build Trivy exporter
  hosts: localhost
  connection: local
  tasks:
    - name: Compile for AMD64
      shell: |
        cd {{ playbook_dir }}
        GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o trivy-exporter-amd64
      args:
        creates: trivy-exporter-amd64

    - name: Compile for ARM64
      shell: |
        cd {{ playbook_dir }}
        GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o trivy-exporter-arm64
      args:
        creates: trivy-exporter-arm64
```

est utilise pour la compilation. Il est plutôt recommandé d'utiliser un pipeline CI/CD avec des outils comme Gitlab CI ou Jenkins que cette méthode.

## Grafana PromQL

Pour voir toutes les CVEs critiques avec leurs détails :

```promql
trivy_vulnerability{severity="CRITICAL"}
```

Pour voir les vulnérabilités d'un package spécifique :

```promql
trivy_vulnerability{package_name="nom_du_package"}
```

Pour compter les vulnérabilités par package :

```promql
count(trivy_vulnerability) by (package_name)
```

Pour voir les packages qui ont des vulnérabilités critiques :

```promql
count(trivy_vulnerability{severity="CRITICAL"}) by (package_name)
```

Pour voir quels packages ont le plus de vulnérabilités :

```promql
topk(10, count(trivy_vulnerability) by (package_name))
```

Pour avoir un tableau des packages vulnerables par serveurs avec les types de vulnérabilités

```promql
count by (instance, package_name, severity) (trivy_vulnerability)
```