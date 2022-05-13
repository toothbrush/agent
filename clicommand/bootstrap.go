package clicommand

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"

	"github.com/buildkite/agent/v3/bootstrap"
	"github.com/buildkite/agent/v3/cliconfig"
	"github.com/buildkite/agent/v3/experiments"
	"github.com/buildkite/agent/v3/logger"
	"github.com/buildkite/agent/v3/process"
	"github.com/urfave/cli"
)

var BootstrapHelpDescription = `Usage:

   buildkite-agent bootstrap [options...]

Description:

   The bootstrap command executes a buildkite job locally.

   Generally the bootstrap command is run as a sub-process of the buildkite-agent to execute
   a given job sent from buildkite.com, but you can also invoke the bootstrap manually.

   Execution is broken down into phases. By default, the bootstrap runs a plugin phase which
   sets up any plugins specified, then a checkout phase which pulls down your code and then a
   command phase that executes the specified command in the created environment.

   You can run only specific phases with the --phases flag.

   The bootstrap is also responsible for executing hooks around the phases.
   See https://buildkite.com/docs/agent/v3/hooks for more details.

Example:

   $ eval $(curl -s -H "Authorization: Bearer xxx" \
     "https://api.buildkite.com/v2/organizations/[org]/pipelines/[proj]/builds/[build]/jobs/[job]/env.txt" | sed 's/^/export /')
   $ buildkite-agent bootstrap --build-path builds`

type BootstrapConfig struct {
	Command                      string   `cli:"command"`
	JobID                        string   `cli:"job" validate:"required"`
	Repository                   string   `cli:"repository" validate:"required"`
	Commit                       string   `cli:"commit" validate:"required"`
	Branch                       string   `cli:"branch" validate:"required"`
	Tag                          string   `cli:"tag"`
	RefSpec                      string   `cli:"refspec"`
	Plugins                      string   `cli:"plugins"`
	PullRequest                  string   `cli:"pullrequest"`
	GitSubmodules                bool     `cli:"git-submodules"`
	SSHKeyscan                   bool     `cli:"ssh-keyscan"`
	AgentName                    string   `cli:"agent" validate:"required"`
	Queue                        string   `cli:"queue"`
	OrganizationSlug             string   `cli:"organization" validate:"required"`
	PipelineSlug                 string   `cli:"pipeline" validate:"required"`
	PipelineProvider             string   `cli:"pipeline-provider" validate:"required"`
	AutomaticArtifactUploadPaths string   `cli:"artifact-upload-paths"`
	ArtifactUploadDestination    string   `cli:"artifact-upload-destination"`
	CleanCheckout                bool     `cli:"clean-checkout"`
	GitCloneFlags                string   `cli:"git-clone-flags"`
	GitFetchFlags                string   `cli:"git-fetch-flags"`
	GitCloneMirrorFlags          string   `cli:"git-clone-mirror-flags"`
	GitCleanFlags                string   `cli:"git-clean-flags"`
	GitMirrorsPath               string   `cli:"git-mirrors-path" normalize:"filepath"`
	GitMirrorsLockTimeout        int      `cli:"git-mirrors-lock-timeout"`
	GitMirrorsSkipUpdate         bool     `cli:"git-mirrors-skip-update"`
	BinPath                      string   `cli:"bin-path" normalize:"filepath"`
	BuildPath                    string   `cli:"build-path" normalize:"filepath"`
	HooksPath                    string   `cli:"hooks-path" normalize:"filepath"`
	PluginsPath                  string   `cli:"plugins-path" normalize:"filepath"`
	CommandEval                  bool     `cli:"command-eval"`
	PluginsEnabled               bool     `cli:"plugins-enabled"`
	PluginValidation             bool     `cli:"plugin-validation"`
	PluginsForcePull             bool     `cli:"plugins-force-pull"`
	LocalHooksEnabled            bool     `cli:"local-hooks-enabled"`
	PTY                          bool     `cli:"pty"`
	Debug                        bool     `cli:"debug"`
	Shell                        string   `cli:"shell"`
	Experiments                  []string `cli:"experiment" normalize:"list"`
	Phases                       []string `cli:"phases" normalize:"list"`
	Profile                      string   `cli:"profile"`
	CancelSignal                 string   `cli:"cancel-signal"`
	RedactedVars                 []string `cli:"redacted-vars" normalize:"list"`
	TracingBackend               string   `cli:"tracing-backend"`
}

var BootstrapCommand = cli.Command{
	Name:        "bootstrap",
	Usage:       "Run a Buildkite job locally",
	Description: BootstrapHelpDescription,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:   "command",
			Value:  "",
			Usage:  "The command to run",
			EnvVar: "BUILDKITE_COMMAND",
		},
		cli.StringFlag{
			Name:   "job",
			Value:  "",
			Usage:  "The ID of the job being run",
			EnvVar: "BUILDKITE_JOB_ID",
		},
		cli.StringFlag{
			Name:   "repository",
			Value:  "",
			Usage:  "The repository to clone and run the job from",
			EnvVar: "BUILDKITE_REPO",
		},
		cli.StringFlag{
			Name:   "commit",
			Value:  "",
			Usage:  "The commit to checkout in the repository",
			EnvVar: "BUILDKITE_COMMIT",
		},
		cli.StringFlag{
			Name:   "branch",
			Value:  "",
			Usage:  "The branch the commit is in",
			EnvVar: "BUILDKITE_BRANCH",
		},
		cli.StringFlag{
			Name:   "tag",
			Value:  "",
			Usage:  "The tag the commit",
			EnvVar: "BUILDKITE_TAG",
		},
		cli.StringFlag{
			Name:   "refspec",
			Value:  "",
			Usage:  "Optional refspec to override git fetch",
			EnvVar: "BUILDKITE_REFSPEC",
		},
		cli.StringFlag{
			Name:   "plugins",
			Value:  "",
			Usage:  "The plugins for the job",
			EnvVar: "BUILDKITE_PLUGINS",
		},
		cli.StringFlag{
			Name:   "pullrequest",
			Value:  "",
			Usage:  "The number/id of the pull request this commit belonged to",
			EnvVar: "BUILDKITE_PULL_REQUEST",
		},
		cli.StringFlag{
			Name:   "agent",
			Value:  "",
			Usage:  "The name of the agent running the job",
			EnvVar: "BUILDKITE_AGENT_NAME",
		},
		cli.StringFlag{
			Name:   "queue",
			Value:  "",
			Usage:  "The name of the queue the agent belongs to, if tagged",
			EnvVar: "BUILDKITE_AGENT_META_DATA_QUEUE",
		},
		cli.StringFlag{
			Name:   "organization",
			Value:  "",
			Usage:  "The slug of the organization that the job is a part of",
			EnvVar: "BUILDKITE_ORGANIZATION_SLUG",
		},
		cli.StringFlag{
			Name:   "pipeline",
			Value:  "",
			Usage:  "The slug of the pipeline that the job is a part of",
			EnvVar: "BUILDKITE_PIPELINE_SLUG",
		},
		cli.StringFlag{
			Name:   "pipeline-provider",
			Value:  "",
			Usage:  "The id of the SCM provider that the repository is hosted on",
			EnvVar: "BUILDKITE_PIPELINE_PROVIDER",
		},
		cli.StringFlag{
			Name:   "artifact-upload-paths",
			Value:  "",
			Usage:  "Paths to files to automatically upload at the end of a job",
			EnvVar: "BUILDKITE_ARTIFACT_PATHS",
		},
		cli.StringFlag{
			Name:   "artifact-upload-destination",
			Value:  "",
			Usage:  "A custom location to upload artifact paths to (for example, s3://my-custom-bucket/and/prefix)",
			EnvVar: "BUILDKITE_ARTIFACT_UPLOAD_DESTINATION",
		},
		cli.BoolFlag{
			Name:   "clean-checkout",
			Usage:  "Whether or not the bootstrap should remove the existing repository before running the command",
			EnvVar: "BUILDKITE_CLEAN_CHECKOUT",
		},
		cli.StringFlag{
			Name:   "git-clone-flags",
			Value:  "-v",
			Usage:  "Flags to pass to \"git clone\" command",
			EnvVar: "BUILDKITE_GIT_CLONE_FLAGS",
		},
		cli.StringFlag{
			Name:   "git-clone-mirror-flags",
			Value:  "-v",
			Usage:  "Flags to pass to \"git clone\" command when mirroring",
			EnvVar: "BUILDKITE_GIT_CLONE_MIRROR_FLAGS",
		},
		cli.StringFlag{
			Name:   "git-clean-flags",
			Value:  "-ffxdq",
			Usage:  "Flags to pass to \"git clean\" command",
			EnvVar: "BUILDKITE_GIT_CLEAN_FLAGS",
		},
		cli.StringFlag{
			Name:   "git-fetch-flags",
			Value:  "",
			Usage:  "Flags to pass to \"git fetch\" command",
			EnvVar: "BUILDKITE_GIT_FETCH_FLAGS",
		},
		cli.StringFlag{
			Name:   "git-mirrors-path",
			Value:  "",
			Usage:  "Path to where mirrors of git repositories are stored",
			EnvVar: "BUILDKITE_GIT_MIRRORS_PATH",
		},
		cli.IntFlag{
			Name:   "git-mirrors-lock-timeout",
			Value:  300,
			Usage:  "Seconds to lock a git mirror during clone, should exceed your longest checkout",
			EnvVar: "BUILDKITE_GIT_MIRRORS_LOCK_TIMEOUT",
		},
		cli.BoolFlag{
			Name:   "git-mirrors-skip-update",
			Usage:  "Skip updating the Git mirror",
			EnvVar: "BUILDKITE_GIT_MIRRORS_SKIP_UPDATE",
		},
		cli.StringFlag{
			Name:   "bin-path",
			Value:  "",
			Usage:  "Directory where the buildkite-agent binary lives",
			EnvVar: "BUILDKITE_BIN_PATH",
		},
		cli.StringFlag{
			Name:   "build-path",
			Value:  "",
			Usage:  "Directory where builds will be created",
			EnvVar: "BUILDKITE_BUILD_PATH",
		},
		cli.StringFlag{
			Name:   "hooks-path",
			Value:  "",
			Usage:  "Directory where the hook scripts are found",
			EnvVar: "BUILDKITE_HOOKS_PATH",
		},
		cli.StringFlag{
			Name:   "plugins-path",
			Value:  "",
			Usage:  "Directory where the plugins are saved to",
			EnvVar: "BUILDKITE_PLUGINS_PATH",
		},
		cli.BoolTFlag{
			Name:   "command-eval",
			Usage:  "Allow running of arbitrary commands",
			EnvVar: "BUILDKITE_COMMAND_EVAL",
		},
		cli.BoolTFlag{
			Name:   "plugins-enabled",
			Usage:  "Allow plugins to be run",
			EnvVar: "BUILDKITE_PLUGINS_ENABLED",
		},
		cli.BoolFlag{
			Name:   "plugin-validation",
			Usage:  "Validate plugin configuration",
			EnvVar: "BUILDKITE_PLUGIN_VALIDATION",
		},
		cli.BoolFlag{
			Name:   "plugins-force-pull",
			Usage:  "Always pull plugin source, even if already present",
			EnvVar: "BUILDKITE_PLUGINS_FORCE_PULL",
		},
		cli.BoolTFlag{
			Name:   "local-hooks-enabled",
			Usage:  "Allow local hooks to be run",
			EnvVar: "BUILDKITE_LOCAL_HOOKS_ENABLED",
		},
		cli.BoolTFlag{
			Name:   "ssh-keyscan",
			Usage:  "Automatically run ssh-keyscan before checkout",
			EnvVar: "BUILDKITE_SSH_KEYSCAN",
		},
		cli.BoolTFlag{
			Name:   "git-submodules",
			Usage:  "Enable git submodules",
			EnvVar: "BUILDKITE_GIT_SUBMODULES",
		},
		cli.BoolTFlag{
			Name:   "pty",
			Usage:  "Run jobs within a pseudo terminal",
			EnvVar: "BUILDKITE_PTY",
		},
		cli.StringFlag{
			Name:   "shell",
			Usage:  "The shell to use to interpret build commands",
			EnvVar: "BUILDKITE_SHELL",
			Value:  DefaultShell(),
		},
		cli.StringSliceFlag{
			Name:   "phases",
			Usage:  "The specific phases to execute. The order they're defined is irrelevant.",
			EnvVar: "BUILDKITE_BOOTSTRAP_PHASES",
		},
		cli.StringFlag{
			Name:   "cancel-signal",
			Usage:  "The signal to use for cancellation",
			EnvVar: "BUILDKITE_CANCEL_SIGNAL",
			Value:  "SIGTERM",
		},
		cli.StringSliceFlag{
			Name:   "redacted-vars",
			Usage:  "Pattern of environment variable names containing sensitive values",
			EnvVar: "BUILDKITE_REDACTED_VARS",
		},
		cli.StringFlag{
			Name:   "tracing-backend",
			Usage:  "The name of the tracing backend to use.",
			EnvVar: "BUILDKITE_TRACING_BACKEND",
			Value:  "",
		},
		DebugFlag,
		ExperimentsFlag,
		ProfileFlag,
	},
	Action: func(c *cli.Context) {
		// The configuration will be loaded into this struct
		cfg := BootstrapConfig{}

		l := CreateLogger(&cfg)

		// Load the configuration
		if err := cliconfig.Load(c, l, &cfg); err != nil {
			l.Fatal("%s", err)
		}

		// Enable experiments
		for _, name := range cfg.Experiments {
			experiments.Enable(name)
		}

		// Enable debug if set
		if cfg.Debug {
			l.SetLevel(logger.DEBUG)
		}

		// Handle profiling flag
		done := HandleProfileFlag(l, cfg)
		defer done()

		// Turn of PTY support if we're on Windows
		runInPty := cfg.PTY
		if runtime.GOOS == "windows" {
			runInPty = false
		}

		// Validate phases
		for _, phase := range cfg.Phases {
			switch phase {
			case "plugin", "checkout", "command":
				// Valid phase
			default:
				l.Fatal("Invalid phase %q", phase)
			}
		}

		cancelSig, err := process.ParseSignal(cfg.CancelSignal)
		if err != nil {
			l.Fatal("Failed to parse cancel-signal: %v", err)
		}

		fmt.Println("before configuring the bootstrapper")
		// Configure the bootstraper
		bootstrap := bootstrap.New(bootstrap.Config{
			AgentName:                    cfg.AgentName,
			ArtifactUploadDestination:    cfg.ArtifactUploadDestination,
			AutomaticArtifactUploadPaths: cfg.AutomaticArtifactUploadPaths,
			BinPath:                      cfg.BinPath,
			Branch:                       cfg.Branch,
			BuildPath:                    cfg.BuildPath,
			CancelSignal:                 cancelSig,
			CleanCheckout:                cfg.CleanCheckout,
			Command:                      cfg.Command,
			CommandEval:                  cfg.CommandEval,
			Commit:                       cfg.Commit,
			Debug:                        cfg.Debug,
			GitCleanFlags:                cfg.GitCleanFlags,
			GitCloneFlags:                cfg.GitCloneFlags,
			GitCloneMirrorFlags:          cfg.GitCloneMirrorFlags,
			GitFetchFlags:                cfg.GitFetchFlags,
			GitMirrorsLockTimeout:        cfg.GitMirrorsLockTimeout,
			GitMirrorsPath:               cfg.GitMirrorsPath,
			GitMirrorsSkipUpdate:         cfg.GitMirrorsSkipUpdate,
			GitSubmodules:                cfg.GitSubmodules,
			HooksPath:                    cfg.HooksPath,
			JobID:                        cfg.JobID,
			LocalHooksEnabled:            cfg.LocalHooksEnabled,
			OrganizationSlug:             cfg.OrganizationSlug,
			Phases:                       cfg.Phases,
			PipelineProvider:             cfg.PipelineProvider,
			PipelineSlug:                 cfg.PipelineSlug,
			PluginValidation:             cfg.PluginValidation,
			Plugins:                      cfg.Plugins,
			PluginsEnabled:               cfg.PluginsEnabled,
			PluginsForcePull:             cfg.PluginsForcePull,
			PluginsPath:                  cfg.PluginsPath,
			PullRequest:                  cfg.PullRequest,
			Queue:                        cfg.Queue,
			RedactedVars:                 cfg.RedactedVars,
			RefSpec:                      cfg.RefSpec,
			Repository:                   cfg.Repository,
			RunInPty:                     runInPty,
			SSHKeyscan:                   cfg.SSHKeyscan,
			Shell:                        cfg.Shell,
			Tag:                          cfg.Tag,
			TracingBackend:               cfg.TracingBackend,
		})

		fmt.Println("after configuring the bootstrapper")

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		signals := make(chan os.Signal, 1)
		signal.Notify(signals, os.Interrupt,
			syscall.SIGHUP,
			syscall.SIGTERM,
			syscall.SIGINT,
			syscall.SIGQUIT)
		defer signal.Stop(signals)

		var (
			cancelled bool
			received  os.Signal
			signalMu  sync.Mutex
		)

		// Listen for signals in the background and cancel the bootstrap
		go func() {
			sig := <-signals
			signalMu.Lock()
			defer signalMu.Unlock()

			// Cancel the bootstrap
			bootstrap.Cancel()

			// Track the state and signal used
			cancelled = true
			received = sig

			// Remove our signal handler so subsequent signals kill
			signal.Stop(signals)
		}()

		// Run the bootstrap and get the exit code
		exitCode := bootstrap.Run(ctx)

		signalMu.Lock()
		defer signalMu.Unlock()

		// If cancelled and our child process returns a non-zero, we should terminate
		// ourselves with the same signal so that our caller can detect and handle appropriately
		if cancelled && runtime.GOOS != `windows` {
			p, err := os.FindProcess(os.Getpid())
			if err != nil {
				l.Error("Failed to find current process: %v", err)
			}

			l.Debug("Terminating bootstrap after cancellation with %v", received)
			err = p.Signal(received)
			if err != nil {
				l.Error("Failed to signal self: %v", err)
			}
		}

		os.Exit(exitCode)
	},
}
