{{/*
Expand the name of the chart.
*/}}
{{- define "registrar.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "registrar.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "registrar.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "registrar.labels" -}}
helm.sh/chart: {{ include "registrar.chart" . }}
{{ include "registrar.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "registrar.selectorLabels" -}}
app.kubernetes.io/name: {{ include "registrar.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "registrar.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "registrar.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the name of the role to use
*/}}
{{- define "registrar.roleName" -}}
{{- default (include "registrar.fullname" .) .Values.role.name }}
{{- end }}

{{/*
Create the name of the role binding to use
*/}}
{{- define "registrar.roleBindingName" -}}
{{- default (include "registrar.fullname" .) .Values.roleBinding.name }}
{{- end }}

{{/*
Expand to the name of the config map to be used
*/}}
{{- define "registrar.configMap" -}}
{{- if .Values.global.configmap.create }}
{{- include "keylime.configMap" . }}
{{- else }}
{{- default (include "keylime.configMap" .) .Values.global.configmap.registrarName }}
{{- end }}
{{- end }}

{{/*
Expand to the secret name for the certificate volume to be used
*/}}
{{- define "registrar.ca.secret" -}}
{{- if .Values.global.ca.generate }}
{{- include "keylime.ca.secret.certs" . }}
{{- else }}
{{- default (include "keylime.ca.secret.certs" .) .Values.global.ca.registrarName }}
{{- end }}
{{- end }}

{{/*
Expand to the replica count, which is conditional on both the value set on the "service"
and "database" sections of global values
*/}}
{{- define "registrar.replicaCount" -}}
{{- if or (eq .Values.global.database.mysql.external true) (eq .Values.global.database.mysql.enable true) }}
{{- default 1 .Values.global.service.registrar.replicas }}
{{- else }}
{{- 1 }}
{{- end }}
{{- end }}

{{/*
Select the service type, based on the value set on the "service" section of global values 
*/}}
{{- define "registrar.serviceType" -}}
{{- if .Values.global.service.registrar.type }}
{{- .Values.global.service.registrar.type }}
{{- else }}
{{- .Values.service.type }}
{{- end }}
{{- end }}

{{/*
Select the load balancer IP, based on the value set on the "service" section of global values 
*/}}
{{- define "registrar.loadBalancerIP" -}}
{{- if .Values.global.service.registrar.loadBalancerIP }}
{{- .Values.global.service.registrar.loadBalancerIP }}
{{- else }}
{{- .Values.service.loadBalancerIP }}
{{- end }}
{{- end }}

{{/*
Expands to the PVC name of the database disk
*/}}
{{- define "registrar.db.pvcName" -}}
{{- $name := printf "%s-database" (include "registrar.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- if .Values.global.database.sqlite.persistence.registrar.create }}
{{- $name }}
{{- else }}
{{- default $name .Values.global.database.sqlite.persistence.registrar.existingClaim }}
{{- end }}
{{- end }}

{{/*
Will expand a whole 'storageClassName: <entry>' section, or nothing if the setting is '-'
*/}}
{{- define "registrar.db.storageClass" -}}
{{- $storageClass := .Values.global.database.sqlite.persistence.registrar.storageClass -}}
{{- if $storageClass -}}
{{- if (eq "-" $storageClass) }}
{{- printf "storageClassName: \"\"" }}
{{- else }}
{{- printf "storageClassName: %s" $storageClass }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Define a custom image repository.
*/}}
{{- define "registrar.image.repository" -}}
{{- if .Values.global.service.registrar.image.repository }}
{{- toYaml .Values.global.service.registrar.image.repository }}
{{- else }}
{{- toYaml .Values.image.repository }}
{{- end }}
{{- end }}

{{/*
Define a custom image tag.
*/}}
{{- define "registrar.image.tag" -}}
{{- if .Values.global.service.registrar.image.tag }}
{{- toYaml .Values.global.service.registrar.image.tag }}
{{- else }}
{{- toYaml .Chart.AppVersion }}
{{- end }}
{{- end }}

{{/*
Define a custom image pullpolicy.
*/}}
{{- define "registrar.image.pullPolicy" -}}
{{- if .Values.global.service.registrar.image.pullPolicy }}
{{- toYaml .Values.global.service.registrar.image.pullPolicy }}
{{- else }}
{{- toYaml .Values.image.pullPolicy }}
{{- end }}
{{- end }}
