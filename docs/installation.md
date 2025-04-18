Guide d'installation

Ce document détaille les étapes d'installation et de configuration d'une solution XDR/SIEM complète basée sur Wazuh.
Installation du serveur Wazuh

Méthode 1: Déploiement avec Docker (recommandée)

    Prérequis

    bash

    # Installer Docker et Docker Compose
    apt update
    apt install -y docker.io docker-compose

    Récupérer les fichiers de configuration

    bash

    git clone https://github.com/wazuh/wazuh-docker.git
    cd wazuh-docker

    Configurer le docker-compose.yml

    bash

    # Modifier les valeurs selon votre environnement
    vi docker-compose.yml

    Lancer les conteneurs

    bash

    docker-compose up -d

Méthode 2: Installation directe

    Ajouter le dépôt Wazuh

    bash

    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
    echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
    apt update

    Installer les composants

    bash

    apt install -y wazuh-manager wazuh-indexer wazuh-dashboard

Installation des agents
Sur Debian/Ubuntu

bash

curl -so wazuh-agent.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.7.3-1_amd64.deb
WAZUH_MANAGER='<IP_DU_MANAGER>' dpkg -i wazuh-agent.deb
systemctl start wazuh-agent
systemctl enable wazuh-agent

Sur CentOS/RHEL

bash

curl -so wazuh-agent.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-4.7.3-1.x86_64.rpm
WAZUH_MANAGER='<IP_DU_MANAGER>' rpm -i wazuh-agent.rpm
systemctl start wazuh-agent
systemctl enable wazuh-agent

Sur Windows

    Télécharger l'installateur depuis packages.wazuh.com
    Exécuter l'installation avec les paramètres suivants:

    powershell

    wazuh-agent-4.7.3-1.msi /q WAZUH_MANAGER="<IP_DU_MANAGER>" WAZUH_AGENT_NAME="windows_agent"

Configuration post-installation
Configuration du Manager

    Vérifier l'installation

    bash

    systemctl status wazuh-manager

    Accéder à l'interface web
        URL: https://<IP_DU_MANAGER>
        Identifiant par défaut: admin
        Mot de passe: Consulter /var/ossec/etc/authd.pass ou les logs de démarrage

Configuration des ports et pare-feu

bash

# Ouvrir les ports nécessaires
ufw allow 1514/tcp  # Communication des agents
ufw allow 1515/tcp  # Enregistrement des agents
ufw allow 443/tcp   # Interface Web
ufw allow 9200/tcp  # Elasticsearch (si exposé)

Intégration Yara et Sigma
Installation de Yara

bash

apt install -y yara

Configuration des règles Yara

    Créer le répertoire des règles

    bash

    mkdir -p /var/ossec/etc/rules/yara_rules

    Ajouter les règles dans ce répertoire

    bash

    # Exemple de règle basique
    echo 'rule suspicious_file {
        meta:
            description = "Detect suspicious files"
        strings:
            $s1 = "cmd.exe /c" nocase
            $s2 = "powershell -exec bypass" nocase
        condition:
            any of them
    }' > /var/ossec/etc/rules/yara_rules/suspicious.yar

    Configurer Wazuh pour utiliser Yara

    bash

    # Ajouter dans ossec.conf
    <ossec_config>
      <command>
        <name>yara</name>
        <executable>yara</executable>
        <extra_args>-r /var/ossec/etc/rules/yara_rules/suspicious.yar</extra_args>
      </command>
    </ossec_config>

Configuration des règles Sigma

    Conversion des règles Sigma en format Wazuh

    bash

    # Utiliser sigma-cli ou sigmac pour la conversion
    # Exemple: sigmac -t wazuh rule.yml -o wazuh_rule.xml

    Ajouter les règles dans le répertoire approprié

    bash

    cp wazuh_rule.xml /var/ossec/etc/rules/sigma_rules/

    Inclure les règles dans la configuration

    xml

    <rule_dir>sigma_rules</rule_dir>

Vérification de l'installation

    Vérifier l'état des services

    bash

    systemctl status wazuh-manager
    systemctl status filebeat  # Si utilisé

    Tester la communication des agents

    bash

    # Sur l'agent
    /var/ossec/bin/agent_control -l

    Vérifier les logs

    bash

    tail -f /var/ossec/logs/ossec.log

    Accéder à l'interface web pour confirmer que tout fonctionne correctement

Troubleshooting

Si vous rencontrez des problèmes, consultez troubleshooting.md pour les solutions aux problèmes courants.
