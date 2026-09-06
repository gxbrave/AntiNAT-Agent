//go:build !linux

package agent

func startLocalUninstallServer(*App) (localUninstallServer, error) { return nil, nil }
