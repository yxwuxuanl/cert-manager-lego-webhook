package chart

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	yamlutil "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"
)

const chartPath = "../../charts/templates"

func helm(t *testing.T, args ...string) ([]byte, error) {
	t.Helper()
	binary := os.Getenv("CHART_TEST_HELM")
	if binary == "" {
		binary = "helm"
	}
	cmd := exec.CommandContext(t.Context(), binary, args...)
	cmd.Env = append(os.Environ(), "KUBECONFIG="+filepath.Join(t.TempDir(), "unused-kubeconfig"))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		return append(output, stderr.Bytes()...), err
	}
	return output, nil
}

func render(t *testing.T, path string, values string, args ...string) map[string]json.RawMessage {
	t.Helper()
	command := []string{"template", "dev", path, "--namespace", "webhook-system"}
	if values != "" {
		file := filepath.Join(t.TempDir(), "values.yaml")
		if err := os.WriteFile(file, []byte(values), 0600); err != nil {
			t.Fatal(err)
		}
		command = append(command, "--values", file)
	}
	output, err := helm(t, append(command, args...)...)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, output)
	}
	decoder := yamlutil.NewYAMLOrJSONDecoder(bytes.NewReader(output), 4096)
	documents := make(map[string]json.RawMessage)
	for {
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		var metadata struct {
			Kind     string `json:"kind"`
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal(raw, &metadata); err != nil {
			t.Fatal(err)
		}
		if metadata.Kind != "" {
			documents[metadata.Kind+"/"+metadata.Metadata.Name] = raw
		}
	}
	return documents
}

func decode[T any](t *testing.T, documents map[string]json.RawMessage, key string) T {
	t.Helper()
	var result T
	if err := json.Unmarshal(documents[key], &result); err != nil {
		t.Fatalf("decode %s: %v", key, err)
	}
	return result
}

func TestDefaultDeployment(t *testing.T) {
	t.Parallel()
	docs := render(t, chartPath, "")
	deployment := decode[appsv1.Deployment](t, docs, "Deployment/dev")
	pod := deployment.Spec.Template.Spec
	container := pod.Containers[0]
	if container.Image != "ghcr.io/yxwuxuanl/cert-manager-lego-webhook:v1.5.0" {
		t.Fatalf("chart maintenance release changed the application image: %s", container.Image)
	}
	if deployment.Spec.Selector.MatchLabels["app"] != "dev" || deployment.Spec.Template.Labels["app"] != "dev" {
		t.Fatal("existing Deployment selector and Pod labels must be preserved for upgrades")
	}
	service := decode[corev1.Service](t, docs, "Service/dev")
	if !reflect.DeepEqual(service.Spec.Selector, deployment.Spec.Selector.MatchLabels) {
		t.Fatal("Service no longer selects webhook Pods")
	}
	security := container.SecurityContext
	if security.AllowPrivilegeEscalation == nil || *security.AllowPrivilegeEscalation {
		t.Fatal("Restricted policy requires allowPrivilegeEscalation=false")
	}
	if security.RunAsNonRoot == nil || !*security.RunAsNonRoot || security.RunAsUser == nil || *security.RunAsUser == 0 {
		t.Fatal("webhook must run as a non-root user")
	}
	if pod.SecurityContext == nil || pod.SecurityContext.SeccompProfile == nil || pod.SecurityContext.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Fatal("Restricted policy requires an explicit seccomp profile")
	}
	if security.Capabilities == nil || !reflect.DeepEqual(security.Capabilities.Drop, []corev1.Capability{"ALL"}) {
		t.Fatal("webhook must drop all capabilities")
	}
	if security.ReadOnlyRootFilesystem == nil || !*security.ReadOnlyRootFilesystem {
		t.Fatal("webhook must retain a read-only root filesystem")
	}
	binding := decode[rbacv1.ClusterRoleBinding](t, docs, "ClusterRoleBinding/dev-cert-manager")
	if binding.Subjects[0].Namespace != "webhook-system" || binding.Subjects[0].Name != "cert-manager" {
		t.Fatalf("incorrect default caller binding: %+v", binding.Subjects)
	}
}

func TestChartVersionDoesNotChangeImage(t *testing.T) {
	t.Parallel()
	copyPath := filepath.Join(t.TempDir(), "chart")
	if err := os.CopyFS(copyPath, os.DirFS(chartPath)); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(copyPath, "Chart.yaml")
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var metadata map[string]any
	if err := yaml.Unmarshal(data, &metadata); err != nil {
		t.Fatal(err)
	}
	metadata["version"] = "9.9.9"
	data, err = yaml.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	deployment := decode[appsv1.Deployment](t, render(t, copyPath, ""), "Deployment/dev")
	if got := deployment.Spec.Template.Spec.Containers[0].Image; got != "ghcr.io/yxwuxuanl/cert-manager-lego-webhook:v1.5.0" {
		t.Fatalf("chart-only version bump changed image: %s", got)
	}
	metadata["appVersion"] = "1.5.99"
	data, err = yaml.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	deployment = decode[appsv1.Deployment](t, render(t, copyPath, ""), "Deployment/dev")
	if got := deployment.Spec.Template.Spec.Containers[0].Image; got != "ghcr.io/yxwuxuanl/cert-manager-lego-webhook:v1.5.99" {
		t.Fatalf("application version bump did not update the default image: %s", got)
	}
}

func TestCustomValuesAndLegacyAffinity(t *testing.T) {
	t.Parallel()
	docs := render(t, chartPath, `
nameOverride: '{{ .Release.Name }}-custom'
certManager:
  namespace: cert-manager
  serviceAccountName: custom-cert-manager
webhook:
  image:
    repository: registry.example.com/team/webhook
    tag: custom-tag
  affinity: []
  replicas: 2
  resources:
    requests:
      cpu: 100m
      memory: 64Mi
  tolerations:
    - key: dedicated
      operator: Exists
  nodeSelector:
    kubernetes.io/os: linux
  dnsConfig:
    nameservers: ["1.1.1.1"]
    options:
      - name: ndots
        value: "1"
  extraArgs: ["--v=2"]
`)
	deployment := decode[appsv1.Deployment](t, docs, "Deployment/dev-custom")
	pod := deployment.Spec.Template.Spec
	if pod.Containers[0].Image != "registry.example.com/team/webhook:custom-tag" || *deployment.Spec.Replicas != 2 {
		t.Fatal("custom image or replica count was ignored")
	}
	if pod.Affinity != nil {
		t.Fatal("legacy empty affinity must remain omitted")
	}
	if pod.DNSPolicy != corev1.DNSNone || !reflect.DeepEqual(pod.DNSConfig.Nameservers, []string{"1.1.1.1"}) {
		t.Fatal("custom DNS settings were ignored")
	}
	if pod.NodeSelector["kubernetes.io/os"] != "linux" || len(pod.Tolerations) != 1 || pod.Containers[0].Resources.Requests.Cpu().String() != "100m" {
		t.Fatal("scheduling or resource settings were ignored")
	}
	if args := pod.Containers[0].Args; args[len(args)-1] != "--v=2" {
		t.Fatal("extraArgs were ignored")
	}
	binding := decode[rbacv1.ClusterRoleBinding](t, docs, "ClusterRoleBinding/dev-custom-cert-manager")
	if binding.Subjects[0].Name != "custom-cert-manager" || binding.Subjects[0].Namespace != "cert-manager" {
		t.Fatalf("custom caller binding was ignored: %+v", binding.Subjects)
	}
}

func TestOptionalValues(t *testing.T) {
	t.Parallel()
	docs := render(t, chartPath, `
groupName: testing
global:
  parentChartValue: allowed
certManager:
  serviceAccountName: ''
webhook:
  replicas: 0
  affinity:
    nodeAffinity:
      requiredDuringSchedulingIgnoredDuringExecution:
        nodeSelectorTerms:
          - matchExpressions:
              - key: kubernetes.io/os
                operator: In
                values: [linux]
`)
	if _, exists := docs["ClusterRoleBinding/dev-cert-manager"]; exists {
		t.Fatal("an empty caller ServiceAccount must disable its binding")
	}
	if _, exists := docs["APIService/v1alpha1.testing"]; !exists {
		t.Fatal("a valid single-label API group must remain supported")
	}
	deployment := decode[appsv1.Deployment](t, docs, "Deployment/dev")
	if *deployment.Spec.Replicas != 0 || deployment.Spec.Template.Spec.Affinity.NodeAffinity == nil {
		t.Fatal("scale-to-zero or affinity object was ignored")
	}
}

func TestInvalidValuesFailEarly(t *testing.T) {
	for _, test := range []struct{ name, values, field string }{
		{"service-account-typo", "certManager:\n  serviceAccount:\n    name: custom\n", "serviceAccount"},
		{"replica-string", "webhook:\n  replicas: oops\n", "replicas"},
		{"replica-negative", "webhook:\n  replicas: -1\n", "replicas"},
		{"affinity-bool", "webhook:\n  affinity: true\n", "affinity"},
		{"affinity-list", "webhook:\n  affinity: [linux]\n", "affinity"},
		{"env-bool", "webhook:\n  envs:\n    LEGO_DISABLE_CNAME_SUPPORT: true\n", "LEGO_DISABLE_CNAME_SUPPORT"},
		{"image-tag-number", "webhook:\n  image:\n    tag: 123\n", "tag"},
		{"image-policy", "webhook:\n  imagePullPolicy: Sometimes\n", "imagePullPolicy"},
		{"dns-missing-nameserver", "webhook:\n  dnsConfig:\n    searches: [example.com]\n", "nameservers"},
		{"extra-args-string", "webhook:\n  extraArgs: --v=2\n", "extraArgs"},
		{"unknown-key", "webhok: {}\n", "webhok"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			file := filepath.Join(t.TempDir(), "invalid.yaml")
			if err := os.WriteFile(file, []byte(test.values), 0600); err != nil {
				t.Fatal(err)
			}
			output, err := helm(t, "template", "dev", chartPath, "--values", file)
			if err == nil || !strings.Contains(string(output), test.field) {
				t.Fatalf("expected validation error identifying %s; got %v\n%s", test.field, err, output)
			}
		})
	}
}

func TestChartPackageIncludesDocumentation(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	output, err := helm(t, "package", chartPath, "--destination", dir)
	if err != nil {
		t.Fatalf("package: %v\n%s", err, output)
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.tgz"))
	if err != nil || len(files) != 1 {
		t.Fatalf("expected one packaged chart, got %v (%v)", files, err)
	}
	output, err = helm(t, "show", "readme", files[0])
	if err != nil || !strings.Contains(string(output), "appVersion") {
		t.Fatalf("package must contain the chart README: %v\n%s", err, output)
	}
	archive, err := os.Open(files[0])
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	compressed, err := gzip.NewReader(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer compressed.Close()
	reader := tar.NewReader(compressed)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			t.Fatal("packaged chart is missing templates/NOTES.txt")
		}
		if err != nil {
			t.Fatal(err)
		}
		if header.Name == "cert-manager-lego-webhook/templates/NOTES.txt" {
			notes, err := io.ReadAll(reader)
			if err != nil || !bytes.Contains(notes, []byte("solverName: lego-solver")) {
				t.Fatalf("package must contain useful NOTES: %v\n%s", err, notes)
			}
			return
		}
	}
}
