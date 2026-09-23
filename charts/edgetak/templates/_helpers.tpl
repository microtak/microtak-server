{{/*
Expand the name of the chart.
*/}}
{{- define "edgetak.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "edgetak.fullname" -}}
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
Common labels.
*/}}
{{- define "edgetak.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{ include "edgetak.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "edgetak.selectorLabels" -}}
app.kubernetes.io/name: {{ include "edgetak.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
The data PVC name to mount: the existing claim if given, otherwise the
release-managed one this chart creates.
*/}}
{{- define "edgetak.dataClaimName" -}}
{{- if .Values.persistence.data.existingClaim }}
{{- .Values.persistence.data.existingClaim }}
{{- else }}
{{- printf "%s-data" (include "edgetak.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Same as above, for the backup PVC.
*/}}
{{- define "edgetak.backupClaimName" -}}
{{- if .Values.persistence.backup.existingClaim }}
{{- .Values.persistence.backup.existingClaim }}
{{- else }}
{{- printf "%s-backup" (include "edgetak.fullname" .) }}
{{- end }}
{{- end }}
