{{- define "appname" -}}
{{- if .Values.nameOverride }}
{{ tpl .Values.nameOverride . }}
{{- else }}
{{ .Release.Name }}
{{- end }}
{{- end -}}