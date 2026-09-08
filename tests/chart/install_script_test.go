package chart

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestWaitForAPIDiscovery(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		waitStatus int
		failures   int
		wantCalls  int
		wantStatus int
		wantOutput string
	}{
		{name: "ready", wantCalls: 1, wantOutput: "discovery ready"},
		{name: "transient unavailable after rollout", failures: 2, wantCalls: 3, wantOutput: "discovery ready"},
		{name: "persistent unavailable", failures: 100, wantCalls: 3, wantStatus: 1, wantOutput: "Timed out waiting for discovery endpoint /apis/test.lego.dns-solver/v1alpha1"},
		{name: "APIService never available", waitStatus: 1, wantStatus: 1, wantOutput: "APIService unavailable"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			// Source only the helpers. Fake kubectl and the clock so these tests
			// exercise retry behavior without a Kubernetes cluster or real sleeps.
			script := fmt.Sprintf(`
source "$1"
unset SECONDS
SECONDS=0
calls=0
sleep() { SECONDS=$((SECONDS + $1)); }
kubectl() {
  case "$1" in
    wait)
      [[ "$*" == 'wait --for=condition=Available apiservice/v1alpha1.test.lego.dns-solver --timeout=5s' ]] || exit 99
      if ((%d != 0)); then
        echo 'APIService unavailable' >&2
        return 1
      fi
      ;;
    get)
      [[ "$*" == 'get --raw /apis/test.lego.dns-solver/v1alpha1 --request-timeout=5s' ]] || exit 99
      calls=$((calls + 1))
      if ((calls <= %d)); then
        echo 'Error from server (ServiceUnavailable)' >&2
        return 1
      fi
      echo 'discovery ready'
      ;;
    *) exit 99 ;;
  esac
}
if wait_for_api test.lego.dns-solver 5; then
  status=0
else
  status=$?
fi
echo "calls=$calls status=$status"
`, tt.waitStatus, tt.failures)
			cmd := exec.CommandContext(ctx, "bash", "-c", script, "test", "../../scripts/test-chart-install.sh")
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("run discovery helper: %v\n%s", err, output)
			}
			wantResult := fmt.Sprintf("calls=%d status=%d", tt.wantCalls, tt.wantStatus)
			if !strings.Contains(string(output), wantResult) || !strings.Contains(string(output), tt.wantOutput) {
				t.Fatalf("expected %q and %q, got:\n%s", wantResult, tt.wantOutput, output)
			}
		})
	}
}
