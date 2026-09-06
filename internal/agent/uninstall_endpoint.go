package agent

import "context"

// UninstallSocketName and UninstallHTTPPath form the stable local HTTP
// transport used by the Linux installer.
const UninstallSocketName = "uninstall.sock"

const UninstallHTTPPath = "/v1/uninstall-notice"

type localUninstallServer interface {
	Close(context.Context) error
}
