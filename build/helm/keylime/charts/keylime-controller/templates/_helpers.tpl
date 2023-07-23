{{/*
Expand the name of the chart.
*/}}
{{- define "keylime-controller.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "keylime-controller.fullname" -}}
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
{{- define "keylime-controller.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "keylime-controller.labels" -}}
helm.sh/chart: {{ include "keylime-controller.chart" . }}
{{ include "keylime-controller.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "keylime-controller.selectorLabels" -}}
app.kubernetes.io/name: {{ include "keylime-controller.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "keylime-controller.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "keylime-controller.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Expand to the name of the config map to be used
*/}}
{{- define "keylime-controller.configMap" -}}
{{- if .Values.global.configmap.create }}
{{- include "keylime.controllerConfigMap" . }}
{{- else }}
{{- default (include "keylime.configMap" .) .Values.global.configmap.controllerName }}
{{- end }}
{{- end }}

{{/*
Expand to the secret name for the certificate volume to be used
*/}}
{{- define "keylime-controller.ca.secret" -}}
{{- if .Values.global.ca.generate }}
{{- include "keylime.ca.secret" . }}
{{- else }}
{{- default (include "keylime.ca.secret" .) .Values.global.ca.controllerName }}
{{- end }}
{{- end }}

{{/*
Expand to the secret name for the TPM cert store volume to be used
*/}}
{{- define "keylime-controller.tpmCertStore.secret" -}}
{{- if .Values.global.tpmCertStore.create }}
{{- include "keylime.tpmCertStore.secret" . }}
{{- else }}
{{- default (include "keylime.tpmCertStore.secret" .) .Values.global.tpmCertStore.name }}
{{- end }}
{{- end }}

{{/*
Expands to true or false if the user selected the fallback TPM cert store mount.
*/}}
{{- define "keylime-controller.enableTpmCertStoreMount" -}}
{{- default true .Values.global.controller.enableTpmCertStoreMount }}
{{- end }}

{{/*
Expands to the secret name for the Secure Payload fallback to be used
*/}}
{{- define "keylime-controller.securePayload.secret" -}}
{{- default "" .Values.global.controller.securePayloadSecretName }}
{{- end }}
