package buildkite

import (
	"fmt"
	"github.com/codegangsta/cli"
	"github.com/oleiade/reflections"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

type Loader struct {
	CLI    *cli.Context
	Config interface{}
}

var CLISpecialNameRegex = regexp.MustCompile(`(arg):(\d+)`)

func Load(c *cli.Context, cfg interface{}) error {
	return Loader{CLI: c, Config: cfg}.Load()
}

func (l Loader) Load() error {
	// Get all the fields from the configuration interface
	var fields []string
	fields, _ = reflections.Fields(l.Config)

	// Loop through each of the fields, and look for tags and handle them
	// appropriately
	for _, fieldName := range fields {
		// Start by loading the value from the CLI context if the tag
		// exists
		cliName, _ := reflections.GetFieldTag(l.Config, fieldName, "cli")
		if cliName != "" {
			// Load the value from the CLI Context
			err := l.setFieldValueFromCLI(fieldName, cliName)
			if err != nil {
				return err
			}
		}

		// Check for field deprecation
		deprecationError, _ := reflections.GetFieldTag(l.Config, fieldName, "deprecated")
		if deprecationError != "" {
			// If the deprecated field's value isn't emtpy, then we
			// return the deprecation error message.
			if !l.fieldValueIsEmpty(fieldName) {
				return fmt.Errorf(deprecationError)
			}
		}

		// Perform validations
		validationRules, _ := reflections.GetFieldTag(l.Config, fieldName, "validate")
		if validationRules != "" {
			// Determine the label for the field
			label, _ := reflections.GetFieldTag(l.Config, fieldName, "label")
			if label == "" {
				// Use the cli name if it exists, but if it
				// doesn't, just default to the structs field
				// name. Not great, but works!
				if cliName != "" {
					label = "--" + cliName
				} else {
					label = fieldName
				}
			}

			// Validate the fieid, and if it fails, return it's
			// error.
			err := l.validateField(fieldName, label, validationRules)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (l Loader) setFieldValueFromCLI(fieldName string, cliName string) error {
	// Get the kind of field we need to set
	fieldKind, err := reflections.GetFieldKind(l.Config, fieldName)
	if err != nil {
		return fmt.Errorf(`Failed to get the type of struct field %s`, fieldName)
	}

	var value interface{}

	// See the if the cli option is using the special format i.e. (arg:1)
	special := CLISpecialNameRegex.FindStringSubmatch(cliName)
	if len(special) == 3 {
		// Should this cli option be loaded from the CLI arguments?
		if special[1] == "arg" {
			// Convert the arg position to an integer
			i, err := strconv.Atoi(special[2])
			if err != nil {
				return fmt.Errorf("Failed to convert string to int: %s", err)
			}

			// Only set the value if the args are long enough for
			// the position to exist.
			if len(l.CLI.Args()) > i {
				// Get the value from the args
				value = l.CLI.Args()[i]
			}
		}
	} else {
		// If the cli name didn't have the special format, then we need to
		// either load from the context's flags, or from a config file.

		// We start by defaulting the value to what ever was provided
		// by the configuration file
		// if configFileValue, ok := configFileMap[cliName]; ok {
		// 	// Convert the config file value to it's correct type
		// 	if fieldKind == reflect.String {
		// 		value = configFileValue
		// 	} else if fieldKind == reflect.Slice {
		// 		value = strings.Split(configFileValue, ",")
		// 	} else if fieldKind == reflect.Bool {
		// 		value, _ = strconv.ParseBool(configFileValue)
		// 	} else {
		// 		return fmt.Errorf("Unable to convert string to type %s", fieldKind)
		// 	}
		// }

		// If a value hasn't been found in a config file, but there
		// _is_ one provided by the CLI context, then use that.
		if value == nil || l.cliValueIsSet(cliName) {
			if fieldKind == reflect.String {
				value = l.CLI.String(cliName)
			} else if fieldKind == reflect.Slice {
				value = l.CLI.StringSlice(cliName)
			} else if fieldKind == reflect.Bool {
				value = l.CLI.Bool(cliName)
			} else {
				return fmt.Errorf("Unable to handle type: %s", fieldKind)
			}
		}
	}

	// Set the value to the cfg
	if value != nil {
		err = reflections.SetField(l.Config, fieldName, value)
		if err != nil {
			return fmt.Errorf("Could not set value `%s` to field `%s` (%s)", value, fieldName, err)
		}
	}

	return nil
}

func (l Loader) cliValueIsSet(cliName string) bool {
	if l.CLI.IsSet(cliName) {
		return true
	} else {
		// cli.Context#IsSet only checks to see if the command was set via the cli, not
		// via the environment. So here we do some hacks to find out the name of the
		// EnvVar, and return true if it was set.
		for _, flag := range l.CLI.Command.Flags {
			name, _ := reflections.GetField(flag, "Name")
			envVar, _ := reflections.GetField(flag, "EnvVar")
			if name == cliName && envVar != "" {
				// Make sure envVar is a string
				if envVarStr, ok := envVar.(string); ok {
					envVarStr = strings.TrimSpace(string(envVarStr))

					return os.Getenv(envVarStr) != ""
				}
			}
		}
	}

	return false
}

func (l Loader) fieldValueIsEmpty(fieldName string) bool {
	// We need to use the field kind to determine the type of empty test.
	value, _ := reflections.GetField(l.Config, fieldName)
	fieldKind, _ := reflections.GetFieldKind(l.Config, fieldName)

	if fieldKind == reflect.String {
		return value == ""
	} else if fieldKind == reflect.Slice {
		v := reflect.ValueOf(value)
		return v.Len() == 0
	} else if fieldKind == reflect.Bool {
		return value == false
	} else {
		panic(fmt.Sprintf("Can't determine empty-ness for field type %s", fieldKind))
	}

	return false
}

func (l Loader) validateField(fieldName string, label string, validationRules string) error {
	// Split up the validation rules
	rules := strings.Split(validationRules, ",")

	// Loop through each rule, and perform it
	for _, rule := range rules {
		if rule == "required" {
			if l.fieldValueIsEmpty(fieldName) {
				return fmt.Errorf("Missing %s. See: `%s %s --help`", label, l.CLI.App.Name, l.CLI.Command.Name)
			}
		} else {
			return fmt.Errorf("Unknown config validation rule `%s`", rule)
		}
	}

	return nil
}
