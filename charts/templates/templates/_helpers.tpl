{{- define "appname" -}}
{{- ternary .Release.Name (tpl .Values.nameOverride .) (not .Values.nameOverride) }}
{{- end -}}