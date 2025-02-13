package clicommand

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/buildkite/agent/v3/internal/bkgql"
	"github.com/buildkite/agent/v3/internal/stdin"
	"github.com/buildkite/agent/v3/logger"
	"github.com/toothbrush/go-pipeline"
	"github.com/toothbrush/go-pipeline/signature"
	"github.com/toothbrush/go-pipeline/warning"
	"github.com/urfave/cli"
	"gopkg.in/yaml.v3"
)

type ToolUnSignConfig struct {
	PipelineFile string `cli:"arg:0" label:"pipeline file"`

	// These change the behaviour
	GraphQLToken string `cli:"graphql-token"`
	Update       bool   `cli:"update"`
	NoConfirm    bool   `cli:"no-confirm"`

	// Enable debug logging for pipeline signing, this depends on debug logging also being enabled
	DebugSigning bool `cli:"debug-signing"`

	// Needed for to use GraphQL API
	OrganizationSlug string `cli:"organization-slug"`
	PipelineSlug     string `cli:"pipeline-slug"`
	GraphQLEndpoint  string `cli:"graphql-endpoint"`

	// Added to signature
	Repository string `cli:"repo"`

	// Global flags
	Debug       bool     `cli:"debug"`
	LogLevel    string   `cli:"log-level"`
	NoColor     bool     `cli:"no-color"`
	Experiments []string `cli:"experiment" normalize:"list"`
	Profile     string   `cli:"profile"`
}

var ToolUnSignCommand = cli.Command{
	Name:  "unsign",
	Usage: "Unsign pipeline steps",
	Description: `Usage:

    buildkite-agent tool unsign [options...] [pipeline-file]

Description:  FOO`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:   "graphql-token",
			Usage:  "A token for the buildkite graphql API. This will be used to populate the value of the repository URL, and download the pipeline definition. Both ′repo′ and ′pipeline-file′ will be ignored in preference of values from the GraphQL API if the token in provided.",
			EnvVar: "BUILDKITE_GRAPHQL_TOKEN",
		},
		cli.BoolFlag{
			Name:   "update",
			Usage:  "Update the pipeline using the GraphQL API after signing it. This can only be used if ′graphql-token′ is provided.",
			EnvVar: "BUILDKITE_TOOL_SIGN_UPDATE",
		},
		cli.BoolFlag{
			Name:   "no-confirm",
			Usage:  "Show confirmation prompts before updating the pipeline with the GraphQL API.",
			EnvVar: "BUILDKITE_TOOL_SIGN_NO_CONFIRM",
		},

		// Used for signing
		cli.BoolFlag{
			Name:   "debug-signing",
			Usage:  "Enable debug logging for pipeline signing. This can potentially leak secrets to the logs as it prints each step in full before signing. Requires debug logging to be enabled",
			EnvVar: "BUILDKITE_AGENT_DEBUG_SIGNING",
		},

		// These are required for GraphQL
		cli.StringFlag{
			Name:   "organization-slug",
			Usage:  "The organization slug. Required to connect to the GraphQL API.",
			EnvVar: "BUILDKITE_ORGANIZATION_SLUG",
		},
		cli.StringFlag{
			Name:   "pipeline-slug",
			Usage:  "The pipeline slug. Required to connect to the GraphQL API.",
			EnvVar: "BUILDKITE_PIPELINE_SLUG",
		},
		cli.StringFlag{
			Name:   "graphql-endpoint",
			Usage:  "The endpoint for the Buildkite GraphQL API. This is only needed if you are using the the graphql-token flag, and is mostly useful for development purposes",
			Value:  bkgql.DefaultEndpoint,
			EnvVar: "BUILDKITE_GRAPHQL_ENDPOINT",
		},

		// Added to signature
		cli.StringFlag{
			Name:   "repo",
			Usage:  "The URL of the pipeline's repository, which is used in the pipeline signature. If the GraphQL token is provided, this will be ignored.",
			EnvVar: "BUILDKITE_REPO",
		},

		// Global flags
		NoColorFlag,
		DebugFlag,
		LogLevelFlag,
		ExperimentsFlag,
		ProfileFlag,
	},

	Action: func(c *cli.Context) error {
		ctx, cfg, l, _, done := setupLoggerAndConfig[ToolUnSignConfig](context.Background(), c)
		defer done()

		var (
			key signature.Key
			err error
		)

		unsign := unsignWithGraphQL
		if cfg.GraphQLToken == "" {
			unsign = unsignOffline
		}

		err = unsign(ctx, c, l, key, &cfg)
		if err != nil {
			return fmt.Errorf("Error unsigning pipeline: %w", err)
		}

		return nil
	},
}

func unsignOffline(ctx context.Context, c *cli.Context, l logger.Logger, key signature.Key, cfg *ToolUnSignConfig) error {
	if cfg.Repository == "" {
		return ErrUseGraphQL
	}

	// Find the pipeline either from STDIN or the first argument
	var (
		input    io.Reader
		filename string
	)

	switch {
	case cfg.PipelineFile != "":
		l.Info("Reading pipeline config from %q", cfg.PipelineFile)

		file, err := os.Open(cfg.PipelineFile)
		if err != nil {
			return fmt.Errorf("failed to read file: %w", err)
		}
		defer file.Close()

		input = file
		filename = cfg.PipelineFile

	case stdin.IsReadable():
		l.Info("Reading pipeline config from STDIN")

		input = os.Stdin
		filename = "(stdin)"

	default:
		return ErrNoPipeline
	}

	pipelineBytes, err := io.ReadAll(input)
	if err != nil {
		return fmt.Errorf("couldn't read pipeline: %w", err)
	}

	err = validateNoInterpolations(string(pipelineBytes))
	if err != nil {
		return err
	}

	parsedPipeline, err := pipeline.Parse(bytes.NewReader(pipelineBytes))
	if err != nil {
		w := warning.As(err)
		if w == nil {
			return fmt.Errorf("pipeline parsing of %q failed: %w", filename, err)
		}
		l.Warn("There were some issues with the pipeline input - signing will be attempted but might not succeed:\n%v", w)
	}

	if cfg.Debug {
		enc := yaml.NewEncoder(c.App.Writer)
		enc.SetIndent(yamlIndent)
		if err := enc.Encode(parsedPipeline); err != nil {
			return fmt.Errorf("couldn't encode pipeline: %w", err)
		}
		l.Debug("Pipeline parsed successfully:\n%v", parsedPipeline)
	}

	err = UnSignSteps(
		ctx,
		parsedPipeline.Steps,
		key,
		cfg.Repository,
		signature.WithEnv(parsedPipeline.Env.ToMap()),
		signature.WithLogger(l),
		signature.WithDebugSigning(cfg.DebugSigning),
	)
	if err != nil {
		return fmt.Errorf("couldn't unsign pipeline: %w", err)
	}

	enc := yaml.NewEncoder(c.App.Writer)
	enc.SetIndent(yamlIndent)
	return enc.Encode(parsedPipeline)
}

func unsignWithGraphQL(ctx context.Context, c *cli.Context, l logger.Logger, key signature.Key, cfg *ToolUnSignConfig) error {
	orgPipelineSlug := fmt.Sprintf("%s/%s", cfg.OrganizationSlug, cfg.PipelineSlug)
	debugL := l.WithFields(logger.StringField("orgPipelineSlug", orgPipelineSlug))

	l.Info("Retrieving pipeline from the GraphQL API")

	client := bkgql.NewClient(cfg.GraphQLEndpoint, cfg.GraphQLToken)

	resp, err := bkgql.GetPipeline(ctx, client, orgPipelineSlug)
	if err != nil {
		return fmt.Errorf("couldn't retrieve pipeline: %w", err)
	}

	if resp.Pipeline.Id == "" {
		return fmt.Errorf(
			"%w: organization-slug: %s, pipeline-slug: %s",
			ErrNotFound,
			cfg.OrganizationSlug,
			cfg.PipelineSlug,
		)
	}

	debugL.Debug("Pipeline retrieved successfully: %#v", resp)

	pipelineString := resp.Pipeline.Steps.Yaml
	err = validateNoInterpolations(pipelineString)
	if err != nil {
		return err
	}

	parsedPipeline, err := pipeline.Parse(strings.NewReader(pipelineString))
	if err != nil {
		w := warning.As(err)
		if w == nil {
			return fmt.Errorf("pipeline parsing failed: %w", err)
		}
		l.Warn("There were some issues with the pipeline input - signing will be attempted but might not succeed:\n%v", w)
	}

	if cfg.Debug {
		enc := yaml.NewEncoder(c.App.Writer)
		enc.SetIndent(yamlIndent)
		if err := enc.Encode(parsedPipeline); err != nil {
			return fmt.Errorf("couldn't encode pipeline: %w", err)
		}
		debugL.Debug("Pipeline parsed successfully: %v", parsedPipeline)
	}

	if err := UnSignSteps(ctx, parsedPipeline.Steps, key, resp.Pipeline.Repository.Url, signature.WithEnv(parsedPipeline.Env.ToMap()), signature.WithLogger(debugL), signature.WithDebugSigning(cfg.DebugSigning)); err != nil {
		return fmt.Errorf("couldn't unsign pipeline: %w", err)
	}

	if !cfg.Update {
		enc := yaml.NewEncoder(c.App.Writer)
		enc.SetIndent(yamlIndent)
		return enc.Encode(parsedPipeline)
	}

	signedPipelineYamlBuilder := &strings.Builder{}
	enc := yaml.NewEncoder(signedPipelineYamlBuilder)
	enc.SetIndent(yamlIndent)
	if err := enc.Encode(parsedPipeline); err != nil {
		return fmt.Errorf("couldn't encode signed pipeline: %w", err)
	}

	signedPipelineYaml := strings.TrimSpace(signedPipelineYamlBuilder.String())
	l.Info("Replacing pipeline with signed version:\n%s", signedPipelineYaml)

	updatePipeline, err := promptConfirmUnsign(
		c, cfg, "\n\x1b[1mAre you sure you want to update the pipeline? This may break your builds!\x1b[0m",
	)
	if err != nil {
		return fmt.Errorf("couldn't read user input: %w", err)
	}

	if !updatePipeline {
		l.Info("Aborting without updating pipeline")
		return nil
	}

	_, err = bkgql.UpdatePipeline(ctx, client, resp.Pipeline.Id, signedPipelineYaml)
	if err != nil {
		return err
	}

	l.Info("Pipeline updated successfully")

	return nil
}

func promptConfirmUnsign(c *cli.Context, cfg *ToolUnSignConfig, message string) (bool, error) {
	if cfg.NoConfirm {
		return true, nil
	}

	if _, err := fmt.Fprintf(c.App.Writer, "%s [y/N]: ", message); err != nil {
		return false, err
	}

	var input string
	if _, err := fmt.Fscanln(os.Stdin, &input); err != nil {
		return false, err
	}
	input = strings.ToLower(input)

	switch input {
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}

func UnSignSteps(ctx context.Context, s pipeline.Steps, key signature.Key, repoURL string, opts ...signature.Option) error {
	for _, step := range s {
		switch step := step.(type) {
		case *pipeline.CommandStep:

			step.Signature = nil

		case *pipeline.GroupStep:
			if err := UnSignSteps(ctx, step.Steps, key, repoURL, opts...); err != nil {
				return fmt.Errorf("unsigning group step: %w", err)
			}

		case *pipeline.UnknownStep:
			// Presence of an unknown step means we're missing some semantic
			// information about the pipeline. We could be not signing something
			// that needs signing. Rather than deferring the problem (so that
			// signature verification fails when an agent runs jobs) we return
			// an error now.
			return errSigningRefusedUnknownStepType
		}
	}
	return nil
}
