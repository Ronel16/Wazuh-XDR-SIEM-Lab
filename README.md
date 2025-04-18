Laboratoire XDR/SIEM avec Wazuh

Ce repository contient la documentation et les configurations pour le déploiement d'une solution XDR/SIEM basée sur Wazuh, déployée sur Proxmox avec intégration de règles Yara et Sigma.

📋 Aperçu du projet

Ce projet vise à créer un laboratoire de cybersécurité complet permettant la détection et la réponse aux menaces. Il utilise Wazuh comme plateforme centrale pour la gestion des événements de sécurité, l'analyse des vulnérabilités et la réponse automatisée aux incidents.

🔧 Technologies utilisées

    Wazuh - Plateforme open-source pour la sécurité et la conformité
    Proxmox - Hyperviseur pour le déploiement des conteneurs
    Docker - Conteneurisation des composants
    Elasticsearch - Indexation et recherche des données
    Kibana - Visualisation et dashboards
    Yara - Règles pour l'identification des malwares
    Sigma - Règles standardisées pour la détection des menaces

🏗️ Architecture

L'architecture se compose de plusieurs composants:

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│    Agent        │     │  Wazuh Manager  │     │  Elasticsearch  │
│   (Proxmox)     │────▶│  (Monitoring)   │────▶│    (Storage)    │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                                                        │
                                                        ▼
                                               ┌─────────────────┐
                                               │     Kibana      │
                                               │  (Visualization) │
                                               └─────────────────┘
```

🚀 Déploiement
Prérequis

    Serveur Proxmox (v7.0+)
    Docker et Docker Compose
    Accès réseau entre les composants

Installation

    Déploiement du Manager Wazuh

    bash

    git clone https://github.com/wazuh/wazuh-docker.git
    cd wazuh-docker
    docker-compose up -d

    Installation des agents

    bash

    # Sur Debian/Ubuntu
    curl -so wazuh-agent.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.7.3-1_amd64.deb
    WAZUH_MANAGER='192.168.2.10' dpkg -i wazuh-agent.deb

🛡️ Configuration
Règles Yara

Les règles Yara sont configurées dans /var/ossec/etc/rules/yara_rules/ et incluent la détection de:

    Malwares connus
    Webshells
    Outils d'attaque

Règles Sigma

Les règles Sigma sont converties et intégrées dans /var/ossec/etc/rules/sigma_rules/ pour détecter:

    Accès suspects
    Élévation de privilèges
    Exécution de code malveillant

Réponses automatisées

Configurations des réponses actives pour:

    Blocage d'IP malveillantes
    Isolement des systèmes compromis
    Notifications en temps réel

📊 Dashboards

Le projet inclut plusieurs tableaux de bord préconfigurés:

    Vue générale de la sécurité
    Détection de vulnérabilités
    Analyse des événements de sécurité
    Suivi des indicateurs de compromission

📚 Documentation

    Guide d'installation
    Guide de configuration

🔄 Maintenance

Instructions pour:

    Mise à jour des règles
    Sauvegarde de la configuration
    Mise à jour des composants

📝 Licence

Ce projet est disponible sous licence MIT - voir le fichier LICENSE pour plus de détails.

📧 Contact

Pour toute question ou suggestion, n'hésitez pas à me contacter à djalilbankole@gmail.com.
