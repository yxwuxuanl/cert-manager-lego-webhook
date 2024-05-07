package main

import (
	"context"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	"os"
)

var (
	GroupName            = os.Getenv("GROUP_NAME")
	CertManagerNamespace = os.Getenv("CERT_MANAGER_NAMESPACE")
)

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	if CertManagerNamespace == "" {
		panic("CERT_MANAGER_NAMESPACE must be specified")
	}

	cmd.RunWebhookServer(GroupName, &LegoSolver{
		ctx: context.Background(),
	})
}
