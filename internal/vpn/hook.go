package vpn

import (
	"context"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/qdm12/log"
)

func executeHook(ctx context.Context, hook string, timeout time.Duration,
	logger log.LoggerInterface, client *http.Client,
) {
	if hook == "" {
		return
	}

	hookCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if strings.HasPrefix(hook, "http://") || strings.HasPrefix(hook, "https://") {
		executeHTTPHook(hookCtx, hook, logger, client)
	} else {
		executeCommandHook(hookCtx, hook, logger)
	}
}

func executeHTTPHook(ctx context.Context, hook string,
	logger log.LoggerInterface, client *http.Client,
) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, hook, nil)
	if err != nil {
		logger.Warn("creating hook HTTP request: " + err.Error())
		return
	}

	response, err := client.Do(request)
	if err != nil {
		logger.Warn("executing hook HTTP request: " + err.Error())
		return
	}
	response.Body.Close()

	if response.StatusCode >= 400 {
		logger.Warnf("hook HTTP request returned status %d", response.StatusCode)
	}
}

func executeCommandHook(ctx context.Context, hook string,
	logger log.LoggerInterface,
) {
	command := exec.CommandContext(ctx, "/bin/sh", "-c", hook) //nolint:gosec
	output, err := command.CombinedOutput()
	if err != nil {
		logger.Warnf("hook command exited with error: %s: %s", err, string(output))
	}
}
