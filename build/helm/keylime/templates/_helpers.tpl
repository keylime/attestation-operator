{{/*
Expand the name of the chart.
*/}}
{{- define "keylime.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "keylime.fullname" -}}
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
{{- define "keylime.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "keylime.labels" -}}
helm.sh/chart: {{ include "keylime.chart" . }}
{{ include "keylime.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "keylime.selectorLabels" -}}
app.kubernetes.io/name: {{ include "keylime.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "keylime.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "keylime.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Expand to the name of the keylime config map
*/}}
{{- define "keylime.configMap" -}}
{{- printf "%s-%s" .Release.Name "keylime" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Always expands to the name of the secret used for certificates when the init job runs.
*/}}
{{- define "keylime.ca.secret" -}}
{{- printf "%s-%s" .Release.Name "keylime-certs" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Always expands to the name of the secret used for the CA certificate when the init job runs.
*/}}
{{- define "keylime.ca.secret.password" -}}
{{- printf "%s-%s" .Release.Name "keylime-ca-password" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Always expands to the name of the secret used for the TPM cert store when the init job runs.
*/}}
{{- define "keylime.tpmCertStore.secret" -}}
{{- printf "%s-%s" .Release.Name "keylime-tpm-cert-store" | trunc 63 | trimSuffix "-" }}
{{- end }}