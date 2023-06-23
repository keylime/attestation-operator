{{/*
Expand the name of the chart.
*/}}
{{- define "verifier.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "verifier.fullname" -}}
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
{{- define "verifier.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "verifier.labels" -}}
helm.sh/chart: {{ include "verifier.chart" . }}
{{ include "verifier.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "verifier.selectorLabels" -}}
app.kubernetes.io/name: {{ include "verifier.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "verifier.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "verifier.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Expand to the name of the config map to be used
*/}}
{{- define "verifier.configMap" -}}
{{- if .Values.global.configmap.create }}
{{- include "keylime.configMap" . }}
{{- else }}
{{- default (include "keylime.configMap" .) .Values.global.configmap.verifierName }}
{{- end }}
{{- end }}

{{/*
Expand to the secret name for the certificate volume to be used
*/}}
{{- define "verifier.ca.secret" -}}
{{- if .Values.global.ca.generate }}
{{- include "keylime.ca.secret" . }}
{{- else }}
{{- default (include "keylime.ca.secret" .) .Values.global.ca.verifierName }}
{{- end }}
{{- end }}

{{/*
Expand to the replica count which is conditional on the database choice if this can scale at all
*/}}
{{- define "verifier.replicaCount" -}}
{{- if .Values.global.database.sqlite.enable }}
{{- 1 }}
{{- else }}
{{- default 1 .Values.replicaCount }}
{{- end }}
{{- end }}

{{/*
Expands to the PVC name of the database disk
*/}}
{{- define "verifier.db.pvcName" -}}
{{- $name := printf "%s-database" (include "verifier.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- if .Values.global.database.sqlite.persistence.verifier.create }}
{{- $name }}
{{- else }}
{{- default $name .Values.global.database.sqlite.persistence.verifier.existingClaim }}
{{- end }}
{{- end }}

{{/*
Will expand a whole 'storageClassName: <entry>' section, or nothing if the setting is '-'
*/}}
{{- define "verifier.db.storageClass" -}}
{{- $storageClass := .Values.global.database.sqlite.persistence.verifier.storageClass -}}
{{- if $storageClass -}}
{{- if (eq "-" $storageClass) }}
{{- printf "storageClassName: \"\"" }}
{{- else }}
{{- printf "storageClassName: %s" $storageClass }}
{{- end }}
{{- end }}
{{- end }}
