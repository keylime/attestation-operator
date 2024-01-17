{{/*
Expand the name of the chart.
*/}}
{{- define "tenant.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "tenant.fullname" -}}
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
{{- define "tenant.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "tenant.labels" -}}
helm.sh/chart: {{ include "tenant.chart" . }}
{{ include "tenant.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "tenant.selectorLabels" -}}
app.kubernetes.io/name: {{ include "tenant.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "tenant.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "tenant.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Expand to the name of the config map to be used
*/}}
{{- define "tenant.configMap" -}}
{{- if .Values.global.configmap.create }}
{{- include "keylime.configMap" . }}
{{- else }}
{{- default (include "keylime.configMap" .) .Values.global.configmap.tenantName }}
{{- end }}
{{- end }}

{{/*
Expand to the secret name for the certificate volume to be used
*/}}
{{- define "tenant.ca.secret" -}}
{{- if .Values.global.ca.generate }}
{{- include "keylime.ca.secret.certs" . }}
{{- else }}
{{- default (include "keylime.ca.secret.certs" .) .Values.global.ca.tenantName }}
{{- end }}
{{- end }}

{{/*
Expand to the secret name for the TPM cert store volume to be used
*/}}
{{- define "tenant.tpmCertStore.secret" -}}
{{- if .Values.global.tpmCertStore.create }}
{{- include "keylime.tpmCertStore.secret" . }}
{{- else }}
{{- default (include "keylime.tpmCertStore.secret" .) .Values.global.tpmCertStore.name }}
{{- end }}
{{- end }}

{{/*
Define a custom image repository.
*/}}
{{- define "tenant.image.repository" -}}
{{- if .Values.global.service.tenant.image.repository }}
{{- toYaml .Values.global.service.tenant.image.repository }}
{{- else }}
{{- toYaml .Values.image.repository }}
{{- end }}
{{- end }}

{{/*
Define a custom image tag.
*/}}
{{- define "tenant.image.tag" -}}
{{- if .Values.global.service.tenant.image.tag }}
{{- toYaml .Values.global.service.tenant.image.tag }}
{{- else }}
{{- toYaml .Chart.AppVersion }}
{{- end }}
{{- end }}
