# trivy-exporter

Ceci est projet pour creer un exporter Prometheus pour Trivy afin d'avoir des metriques temporels pouvoir l'integrer dans un dashboard Grafana.

Dans ce dossier il y a deux parties. La partie de l'exporter en code source golang et la partie ansible pour le deploiement

## trivy Exporter

>![Warning] Je precise que ce projet est fait pour exporter le resultat d'un scan trivy pour les CVEs. Ca a ete cree uniquement dans ce besoin precis et pour me familiarise avec le langage Golang.

Les dependances supplementaire suivante son necessaire pour la compilation

```golang
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
```

## Ansible

La partie ansible est presente pour facilite le deploiement de l'exporter. La premiere partie du playbook

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

est utilise pour la compilation. Il est plutot recommander d'utiliser un pipeline CI/CD avec des outils comme Gitlab CI ou Jenkins que cette methode.