{{- define "appname" -}}
{{- ternary .Release.Name (tpl .Values.nameOverride .) (not .Values.nameOverride) }}
{{- end -}}

{{- define "cert-manager-lego-webhook.image" -}}
{{- printf "%s:%s" .Values.webhook.image.repository (default (printf "v%s" .Chart.AppVersion) .Values.webhook.image.tag) -}}
{{- end -}}
