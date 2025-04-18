Guide de configuration

Ce document détaille les configurations avancées pour optimiser votre solution XDR/SIEM basée sur Wazuh.
Configuration de base
Fichier de configuration principal

Le fichier principal de configuration de Wazuh se trouve à /var/ossec/etc/ossec.conf. Voici un exemple de configuration optimisée:

xml

<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>no</logall_json>
    <email_notification>yes</email_notification>
    <smtp_server>smtp.example.com</smtp_server>
    <email_from>wazuh@example.com</email_from>
    <email_to>admin@example.com</email_to>
    <email_maxperhour>12</email_maxperhour>
  </global>

  <alerts>
    <log_alert_level>3</log_alert_level>
    <email_alert_level>10</email_alert_level>
  </alerts>

  <!-- Configurations supplémentaires -->
</ossec_config>

Configuration des modules de sécurité
Surveillance d'intégrité des fichiers (FIM)

xml

<syscheck>
  <disabled>no</disabled>
  <frequency>43200</frequency>
  <scan_on_start>yes</scan_on_start>
  <alert_new_files>yes</alert_new_files>
  <auto_ignore>no</auto_ignore>
  
  <!-- Répertoires critiques à surveiller -->
  <directories check_all="yes">/etc,/usr/bin,/usr/sbin</directories>
  <directories check_all="yes">/bin,/sbin</directories>
  
  <!-- Répertoires spécifiques à Proxmox -->
  <directories check_all="yes">/etc/pve</directories>
  <directories check_all="yes">/var/lib/pve-cluster</directories>
  
  <!-- Fichiers à ignorer -->
  <ignore>/etc/mtab</ignore>
  <ignore>/etc/hosts.deny</ignore>
  <ignore>/var/ossec/queue</ignore>
</syscheck>

Détection de vulnérabilités

xml

<vulnerability-detector>
  <enabled>yes</enabled>
  <interval>1d</interval>
  <run_on_start>yes</run_on_start>
  
  <!-- Fournisseurs de bases de données de vulnérabilités -->
  <provider name="canonical">
    <enabled>yes</enabled>
    <os>trusty</os>
    <os>xenial</os>
    <os>bionic</os>
    <os>focal</os>
    <os>jammy</os>
    <update_interval>1h</update_interval>
  </provider>
  
  <provider name="debian">
    <enabled>yes</enabled>
    <os>stretch</os>
    <os>buster</os>
    <os>bullseye</os>
    <update_interval>1h</update_interval>
  </provider>
</vulnerability-detector>

Configuration de la surveillance réseau

xml

<wodle name="syscollector">
  <disabled>no</disabled>
  <interval>1h</interval>
  <scan_on_start>yes</scan_on_start>
  <hardware>yes</hardware>
  <os>yes</os>
  <network>yes</network>
  <packages>yes</packages>
  <ports all="no">yes</ports>
  <processes>yes</processes>
</wodle>

Configuration des règles personnalisées
Règles locales

Créez un fichier /var/ossec/etc/rules/local_rules.xml:

xml

<group name="local,">
  <!-- Règle pour les connexions SSH échouées multiples -->
  <rule id="100001" level="10">
    <if_sid>5710</if_sid>
    <same_source_ip />
    <occurred>5</occurred>
    <time_frame>120</time_frame>
    <description>Multiple SSH authentication failures from same source.</description>
    <group>authentication_failures,pci_dss_10.2.4,pci_dss_10.2.5,</group>
  </rule>
  
  <!-- Règle pour les modifications de fichiers critiques sur Proxmox -->
  <rule id="100002" level="12">
    <if_sid>550</if_sid>
    <match>/etc/pve|/var/lib/pve-cluster</match>
    <description>Critical Proxmox configuration file modified.</description>
    <group>pci_dss_10.5.2,proxmox,</group>
  </rule>
</group>

Intégration des règles Yara

    Créez un répertoire pour les règles Yara:

    bash

    mkdir -p /var/ossec/etc/rules/yara_rules

    Ajoutez des règles Yara pour détecter les malwares courants:

    bash

    # Exemple de règle Yara pour détecter un webshell
    echo 'rule php_webshell {
        meta:
            description = "Détecte les webshells PHP"
        strings:
            $s1 = "eval($_" nocase
            $s2 = "shell_exec" nocase
            $s3 = "system(" nocase
            $s4 = "passthru" nocase
            $s5 = "preg_replace" nocase
        condition:
            filesize < 200KB and 2 of them
    }' > /var/ossec/etc/rules/yara_rules/webshells.yar

    Configurez l'intégration dans ossec.conf:

    xml

    <command>
      <name>yara</name>
      <executable>yara</executable>
      <timeout_allowed>yes</timeout_allowed>
    </command>

    <active-response>
      <command>yara</command>
      <location>local</location>
      <rules_id>100003</rules_id>
    </active-response>

Intégration des règles Sigma

    Convertissez les règles Sigma en format Wazuh:

    bash

    # Exemple avec sigmac
    sigmac -t wazuh -c fieldmappings.config path/to/sigma/rule.yml > wazuh_sigma_rule.xml

    Ajoutez les règles converties au répertoire de règles:

    bash

    mkdir -p /var/ossec/etc/rules/sigma_rules
    cp wazuh_sigma_rule.xml /var/ossec/etc/rules/sigma_rules/

    Incluez le répertoire de règles dans ossec.conf:

    xml

    <ossec_config>
      <ruleset>
        <rule_dir>sigma_rules</rule_dir>
      </ruleset>
    </ossec_config>

Configuration des réponses actives

Les réponses actives permettent à Wazuh de réagir automatiquement aux menaces:

xml

<command>
  <name>firewall-drop</name>
  <executable>firewall-drop</executable>
  <expect>srcip</expect>
  <timeout_allowed>yes</timeout_allowed>
</command>

<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <level>7</level>
  <timeout>600</timeout>
</active-response>

Configuration d'alertes et notifications
Notifications par email

xml

<global>
  <email_notification>yes</email_notification>
  <smtp_server>smtp.gmail.com</smtp_server>
  <smtp_port>587</smtp_port>
  <email_from>wazuh.alerts@example.com</email_from>
  <email_to>admin@example.com</email_to>
  <email_maxperhour>12</email_maxperhour>
  <email_log_source>alerts.log</email_log_source>
  <smtp_auth>yes</smtp_auth>
  <smtp_auth_username>wazuh.alerts@example.com</smtp_auth_username>
  <smtp_auth_password>password</smtp_auth_password>
</global>

Intégration avec Slack

xml

<integration>
  <name>slack</name>
  <hook_url>https://hooks.slack.com/services/T0XXXXX/BXXXXXX/XXXXXXXX</hook_url>
  <alert_format>json</alert_format>
  <level>7</level>
</integration>

Optimisation des performances
Ajustement de la mémoire pour Elasticsearch

Modifiez le fichier /etc/elasticsearch/jvm.options:

-Xms4g
-Xmx4g

Configuration de la rotation des logs

xml

<logging>
  <log_format>plain</log_format>
  <max_log_size>100M</max_log_size>
  <num_max_log_files>30</num_max_log_files>
</logging>

Optimisation des agents

Sur les agents avec ressources limitées:

xml

<client_buffer>
  <disabled>no</disabled>
  <queue_size>5000</queue_size>
  <events_per_second>500</events_per_second>
</client_buffer>

<syscheck>
  <frequency>86400</frequency>
  <process_priority>10</process_priority>
  <max_eps>100</max_eps>
</syscheck>

Application des configurations

Après avoir effectué des modifications de configuration:

bash

# Vérifier la syntaxe de la configuration
/var/ossec/bin/ossec-logtest

# Redémarrer le service
systemctl restart wazuh-manager

# Vérifier le statut
systemctl status wazuh-manager

Consultez les logs pour confirmer que les changements ont été appliqués:

bash

tail -f /var/ossec/logs/ossec.log

