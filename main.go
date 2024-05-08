package main

import (
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	"os"
)

var (
	GroupName = os.Getenv("GROUP_NAME")
)

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	cmd.RunWebhookServer(GroupName, &LegoSolver{})
}
