package bootstrap

import (
	"reflect"
	"strconv"

	"log"

	"github.com/buildkite/agent/v3/env"
	"github.com/buildkite/agent/v3/process"
)

// Config provides the configuration for the Bootstrap. Some of the keys are
// read from the environment after hooks are run, so we use struct tags to provide
// that mapping along with some reflection. It's a little bit magical but it's
// less work to maintain in the long run.
//
// To add a new config option that is mapped from an env, add a struct tag and it's done
type Config struct {
	// The command to run
	Command string

	// The ID of the job being run
	JobID string

	// If the bootstrap is in debug mode
	Debug bool

	// The repository that needs to be cloned
	Repository string `env:"BUILDKITE_REPO"`

	// The commit being built
	Commit string

	// The branch of the commit
	Branch string

	// The tag of the job commit
	Tag string

	// Optional refspec to override git fetch
	RefSpec string `env:"BUILDKITE_REFSPEC"`

	// Plugin definition for the job
	Plugins string

	// Should git submodules be checked out
	GitSubmodules bool

	// If the commit was part of a pull request, this will container the PR number
	PullRequest string

	// The provider of the pipeline
	PipelineProvider string

	// Slug of the current organization
	OrganizationSlug string

	// Slug of the current pipeline
	PipelineSlug string

	// Name of the agent running the bootstrap
	AgentName string

	// Name of the queue the agent belongs to, if tagged
	Queue string

	// Should the bootstrap remove an existing checkout before running the job
	CleanCheckout bool `env:"BUILDKITE_CLEAN_CHECKOUT"`

	// Flags to pass to "git clone" command
	GitCloneFlags string `env:"BUILDKITE_GIT_CLONE_FLAGS"`

	// Flags to pass to "git fetch" command
	GitFetchFlags string `env:"BUILDKITE_GIT_FETCH_FLAGS"`

	// Flags to pass to "git clone" command for mirroring
	GitCloneMirrorFlags string

	// Flags to pass to "git clean" command
	GitCleanFlags string `env:"BUILDKITE_GIT_CLEAN_FLAGS"`

	// Whether or not to run the hooks/commands in a PTY
	RunInPty bool

	// Are arbitrary commands allowed to be executed
	CommandEval bool

	// Are plugins enabled?
	PluginsEnabled bool

	// todo mention inspiration https://github.com/buildkite/agent/pull/1242
	// Should we always force a pull of plugins, even if we have a local checkout?
	PluginsForcePull bool `env:"BUILDKITE_PLUGINS_FORCE_PULL"`

	// Whether to validate plugin configuration
	PluginValidation bool

	// Are local hooks enabled?
	LocalHooksEnabled bool

	// Path where the builds will be run
	BuildPath string

	// Path where the repository mirrors are stored
	GitMirrorsPath string

	// Seconds to wait before allowing git mirror clone lock to be acquired
	GitMirrorsLockTimeout int

	// Skip updating the Git mirror before using it
	GitMirrorsSkipUpdate bool `env:"BUILDKITE_GIT_MIRRORS_SKIP_UPDATE"`

	// Path to the buildkite-agent binary
	BinPath string

	// Path to the global hooks
	HooksPath string

	// Path to the plugins directory
	PluginsPath string

	// Paths to automatically upload as artifacts when the build finishes
	AutomaticArtifactUploadPaths string `env:"BUILDKITE_ARTIFACT_PATHS"`

	// A custom destination to upload artifacts to (for example, s3://...)
	ArtifactUploadDestination string `env:"BUILDKITE_ARTIFACT_UPLOAD_DESTINATION"`

	// Whether ssh-keyscan is run on ssh hosts before checkout
	SSHKeyscan bool

	// The shell used to execute commands
	Shell string

	// Phases to execute, defaults to all phases
	Phases []string

	// What signal to use for command cancellation
	CancelSignal process.Signal

	// List of environment variable globs to redact from job output
	RedactedVars []string

	// Backend to use for tracing. If an empty string, no tracing will occur.
	TracingBackend string
}

// ReadFromEnvironment reads configuration from the Environment, returns a map
// of the env keys that changed and the new values
func (c *Config) ReadFromEnvironment(environ *env.Environment) map[string]string {
	changed := map[string]string{}

	// Use reflection for the type and values
	fields := reflect.TypeOf(*c)
	values := reflect.ValueOf(c).Elem()

	// Iterate over all available fields and read the tag value
	for i := 0; i < fields.NumField(); i++ {
		f := fields.Field(i)
		v := values.Field(i)

		// Find struct fields with env tag
		if tag := f.Tag.Get("env"); tag != "" && environ.Exists(tag) {
			newStr, _ := environ.Get(tag)

			switch v.Kind() {
			case reflect.String:
				if newStr == v.String() {
					break
				}
				v.SetString(newStr)
				changed[tag] = newStr
			case reflect.Bool:
				newBool, err := strconv.ParseBool(newStr)
				if err != nil {
					log.Printf("warning: cannot parse %s=%s as bool, ignoring", tag, newStr)
					break
				}
				if newBool == v.Bool() {
					break
				}
				v.SetBool(newBool)
				changed[tag] = newStr
			default:
				log.Printf("warning: bootstrap.Config.ReadFromEnvironment does not support %v for %s", v.Kind(), tag)
			}
		}
	}

	return changed
}
