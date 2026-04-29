// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: BUSL-1.1

package seal_binary

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/api"
	dockhelper "github.com/hashicorp/vault/sdk/helper/docker"
	"github.com/hashicorp/vault/sdk/helper/testcluster/docker"
	client "github.com/moby/moby/client"
)

const (
	containerConfig = `
{
	"storage": {
		"file": {
			"path": "/tmp"
		}
	},

	"disable_mlock": true,

	"listener": [{
		"tcp": {
			"address": "0.0.0.0:8200",
			"tls_disable": "true"
		}
	}],

	"api_addr": "http://0.0.0.0:8200",
	"cluster_addr": "http://0.0.0.0:8201",
	%s
}`

	sealConfig = `
"seal": [
	%s
]
`

	transitParameters = `
  "address": "%s",
  "token": "%s",
  "mount_path": "%s",
  "key_name": "%s",
  "name": "%s"
`

	transitStanza = `
{
	"transit": {
	  %s,
	  "priority": %d,
	  "disabled": %s
	}
}
`
	// recoveryModeFileName serves as a signal for the softhsmSetupScript to add the `-recovery` flag
	// when launching Vault.
	recoveryModeFileName     = "start-in-recovery-mode"
	recoveryModeFileDir      = "/root/"
	recoveryModeFileContents = "Script setup-softhsm.sh looks for this file and starts vault in recovery mode if it sees it"
)

type transitContainerConfig struct {
	Address    string
	Token      string
	MountPaths []string
	KeyNames   []string
}

func createBuildContextWithBinary(vaultBinary string) (dockhelper.BuildContext, error) {
	f, err := os.Open(vaultBinary)
	if err != nil {
		return nil, fmt.Errorf("error opening vault binary file: %w", err)
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("error reading vault binary file: %w", err)
	}

	bCtx := dockhelper.NewBuildContext()
	bCtx["vault"] = &dockhelper.FileContents{
		Data: data,
		Mode: 0o755,
	}

	return bCtx, nil
}

func createDockerImage(imageRepo, imageTag, containerFile string, bCtx dockhelper.BuildContext) error {
	runner, err := dockhelper.NewServiceRunner(dockhelper.RunOptions{
		ContainerName: "vault",
		ImageRepo:     imageRepo,
		ImageTag:      "latest",
	})
	if err != nil {
		return fmt.Errorf("error creating runner: %w", err)
	}

	_, err = runner.BuildImage(context.Background(), containerFile, bCtx,
		dockhelper.BuildRemove(true),
		dockhelper.BuildForceRemove(true),
		dockhelper.BuildPullParent(true),
		dockhelper.BuildTags([]string{fmt.Sprintf("%s:%s", imageRepo, imageTag)}))
	if err != nil {
		return fmt.Errorf("error building docker image: %w", err)
	}

	return nil
}

// This passes the config in an environment variable, so any changes to local.json
// on the container will be overwritten if the container restarts
func createContainerWithConfig(config string, imageRepo, imageTag string, logConsumer func(s string)) (*dockhelper.Service, *dockhelper.Runner, error) {
	runner, err := dockhelper.NewServiceRunner(dockhelper.RunOptions{
		ContainerName: "vault",
		ImageRepo:     imageRepo,
		ImageTag:      imageTag,
		Cmd: []string{
			"server", "-log-level=trace",
		},
		Ports: []string{"8200/tcp"},
		Env: []string{
			fmt.Sprintf("VAULT_LICENSE=%s", os.Getenv("VAULT_LICENSE")),
			fmt.Sprintf("VAULT_LOCAL_CONFIG=%s", config),
			"SKIP_SETCAP=true",
		},
		LogConsumer:     logConsumer,
		DoNotAutoRemove: true,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("error creating runner: %w", err)
	}

	svc, err := runner.StartService(context.Background(), func(ctx context.Context, host string, port int) (dockhelper.ServiceConfig, error) {
		return *dockhelper.NewServiceURL(url.URL{Scheme: "http", Host: fmt.Sprintf("%s:%d", host, port)}), nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("could not start docker vault: %w", err)
	}

	return svc, runner, nil
}

func createContainerFromImage(imageRepo, imageTag string, logConsumer func(s string)) (*dockhelper.Service, *dockhelper.Runner, error) {
	return createContainerWithConfig("", imageRepo, imageTag, logConsumer)
}

func createTransitTestContainer(imageRepo, imageTag string, numKeys int) (*dockhelper.Service, *transitContainerConfig, error) {
	rootToken, err := uuid.GenerateUUID()
	if err != nil {
		return nil, nil, fmt.Errorf("error generating UUID: %w", err)
	}

	mountPaths := make([]string, numKeys)
	keyNames := make([]string, numKeys)

	for i := range mountPaths {
		mountPaths[i], err = uuid.GenerateUUID()
		if err != nil {
			return nil, nil, fmt.Errorf("error generating UUID: %w", err)
		}

		keyNames[i], err = uuid.GenerateUUID()
		if err != nil {
			return nil, nil, fmt.Errorf("error generating UUID: %w", err)
		}
	}

	runner, err := dockhelper.NewServiceRunner(dockhelper.RunOptions{
		ContainerName: "vault",
		ImageRepo:     imageRepo,
		ImageTag:      imageTag,
		Cmd: []string{
			"server", "-log-level=trace", "-dev", fmt.Sprintf("-dev-root-token-id=%s", rootToken),
			"-dev-listen-address=0.0.0.0:8200",
		},
		Env:   []string{fmt.Sprintf("VAULT_LICENSE=%s", os.Getenv("VAULT_LICENSE")), "SKIP_SETCAP=true"},
		Ports: []string{"8200/tcp"},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("could not create runner: %w", err)
	}

	svc, err := runner.StartService(context.Background(), func(ctx context.Context, host string, port int) (dockhelper.ServiceConfig, error) {
		c := *dockhelper.NewServiceURL(url.URL{Scheme: "http", Host: fmt.Sprintf("%s:%d", host, port)})

		clientConfig := api.DefaultConfig()
		clientConfig.Address = c.URL().String()
		vault, err := api.NewClient(clientConfig)
		if err != nil {
			return nil, err
		}
		vault.SetToken(rootToken)

		// Set up transit mounts and keys
		for i := range mountPaths {
			if err := vault.Sys().Mount(mountPaths[i], &api.MountInput{
				Type: "transit",
			}); err != nil {
				return nil, err
			}

			if _, err := vault.Logical().Write(path.Join(mountPaths[i], "keys", keyNames[i]), map[string]interface{}{}); err != nil {
				return nil, err
			}
		}

		return c, nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("could not start docker vault: %w", err)
	}

	mapping, err := runner.GetNetworkAndAddresses(svc.Container.Name)
	if err != nil {
		svc.Cleanup()
		return nil, nil, fmt.Errorf("failed to get container network information: %w", err)
	}

	if len(mapping) != 1 {
		svc.Cleanup()
		return nil, nil, fmt.Errorf("expected 1 network mapping, got %d", len(mapping))
	}

	var ip string
	for _, ip = range mapping {
		// capture the container IP address from the map
	}

	return svc,
		&transitContainerConfig{
			Address:    fmt.Sprintf("http://%s:8200", ip),
			Token:      rootToken,
			MountPaths: mountPaths,
			KeyNames:   keyNames,
		}, nil
}

func validateVaultStatusAndSealType(client *api.Client, expectedSealType string) error {
	statusResp, err := client.Sys().SealStatus()
	if err != nil {
		return fmt.Errorf("error getting vault status: %w", err)
	}

	if statusResp.Sealed {
		return fmt.Errorf("expected vault to be unsealed, but it is sealed")
	}

	if statusResp.Type != expectedSealType {
		return fmt.Errorf("unexpected seal type: expected %s, got %s", expectedSealType, statusResp.Type)
	}

	return nil
}

func testClient(address string) (*api.Client, error) {
	clientConfig := api.DefaultConfig()
	clientConfig.Address = address
	testClient, err := api.NewClient(clientConfig)
	if err != nil {
		return nil, err
	}
	return testClient, nil
}

func initializeVault(client *api.Client, sealType string) ([]string, string, error) {
	var keys []string
	var token string

	if sealType == "shamir" {
		initResp, err := client.Sys().Init(&api.InitRequest{
			SecretThreshold: 1,
			SecretShares:    1,
		})
		if err != nil {
			return nil, "", err
		}

		keys = initResp.Keys
		token = initResp.RootToken

		_, err = client.Sys().Unseal(initResp.Keys[0])
		if err != nil {
			return nil, "", err
		}
	} else {
		initResp, err := client.Sys().Init(&api.InitRequest{
			RecoveryShares:    1,
			RecoveryThreshold: 1,
		})
		if err != nil {
			return nil, "", err
		}

		keys = initResp.RecoveryKeys
		token = initResp.RootToken
	}

	return keys, token, nil
}

func copyConfigToContainer(containerID string, bCtx dockhelper.BuildContext, runner *dockhelper.Runner) error {
	tar, err := bCtx.ToTarball()
	if err != nil {
		return fmt.Errorf("error creating config tarball: %w", err)
	}

	_, err = runner.DockerAPI.CopyToContainer(context.Background(), containerID, client.CopyToContainerOptions{
		DestinationPath: "/vault/config",
		Content:         tar,
	})
	if err != nil {
		return fmt.Errorf("error copying config to container: %w", err)
	}

	return nil
}

func copyRecoveryModeTriggerToContainer(containerID string, runner *dockhelper.Runner) error {
	bCtx := dockhelper.NewBuildContext()
	bCtx[recoveryModeFileName] = &dockhelper.FileContents{
		Data: []byte(recoveryModeFileContents),
		Mode: 0o644,
	}
	tar, err := bCtx.ToTarball()
	if err != nil {
		return fmt.Errorf("error creating config tarball: %w", err)
	}

	_, err = runner.DockerAPI.CopyToContainer(context.Background(), containerID, client.CopyToContainerOptions{
		DestinationPath: recoveryModeFileDir,
		Content:         tar,
	})
	if err != nil {
		return fmt.Errorf("error copying revovery mode trigger file to container: %w", err)
	}
	return nil
}

func dockerOptions(t *testing.T, repo, tag string) *docker.DockerClusterOptions {
	opts := docker.DefaultOptions(t)
	opts.NumCores = 1
	opts.VaultBinary = os.Getenv("VAULT_BINARY")
	opts.ImageRepo, opts.ImageTag = repo, tag
	// Probably not reliable in CI with multi-node clusters, but we're assuming callers
	// of this func won't change NumCores to be >1.
	opts.VaultNodeConfig.StorageOptions = map[string]string{
		"performance_multiplier": "1",
	}
	return opts
}

type logScanner struct {
	wg   sync.WaitGroup
	l    sync.Mutex
	ch   chan string
	pw   *io.PipeWriter
	stop chan struct{}
}

func newLogScanner(t *testing.T, underlying io.Writer, bufLines int) (*logScanner, io.Writer) {
	pr, pw := io.Pipe()
	ls := &logScanner{
		ch:   make(chan string, bufLines),
		pw:   pw,
		stop: make(chan struct{}),
	}

	ls.wg.Add(1)
	go func() {
		defer ls.wg.Done()
		// bufio.Scanner is perfect here because hclog writes each log entry
		// ending with a newline character.
		scanner := bufio.NewScanner(pr)

		// scanner.Scan() will block until a new line is written to the pipe,
		// and it will exit automatically when pw.Close() is called.
		for scanner.Scan() {
			logLine := scanner.Text()
			underlying.Write([]byte(logLine + "\n"))
			select {
			case <-ls.stop:
				return
			case ls.ch <- logLine:
			}
		}

		if err := scanner.Err(); err != nil {
			t.Fatalf("Scanner error: %v", err)
		}
	}()

	t.Cleanup(func() {
		if err := ls.Close(); err != nil {
			t.Logf("Error closing scanner: %v", err)
		}
	})

	return ls, pw
}

func (ls *logScanner) Lines() <-chan string {
	return ls.ch
}

func (ls *logScanner) Close() error {
	ls.l.Lock()
	defer ls.l.Unlock()

	close(ls.stop)
	err := ls.pw.Close()
	ls.wg.Wait()

	return err
}

type logMatcher struct {
	targets map[string]bool
	lines   <-chan string
	done    chan struct{}
	l       sync.RWMutex
}

func newLogMatcher(lines <-chan string, targets []string) *logMatcher {
	tmap := make(map[string]bool)
	for _, target := range targets {
		tmap[target] = false
	}
	lm := &logMatcher{
		targets: tmap,
		lines:   lines,
		done:    make(chan struct{}),
	}

	go func() {
		for {
			select {
			case <-lm.done:
				return
			case line := <-lines:
				for target, ok := range tmap {
					if !ok && strings.Contains(line, target) {
						lm.l.Lock()
						tmap[target] = true
						lm.l.Unlock()
					}
				}
			}
		}
	}()

	return lm
}

func (lm *logMatcher) stop() {
	close(lm.done)
}

func (lm *logMatcher) missing() []string {
	lm.l.RLock()
	defer lm.l.RUnlock()

	var ret []string
	for target, found := range lm.targets {
		if !found {
			ret = append(ret, target)
		}
	}
	return ret
}
