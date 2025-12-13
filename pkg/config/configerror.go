package config

import (
	"errors"
	"log/slog"

	"github.com/spf13/cast"

	"github.com/italypaleale/tsiam/pkg/utils"
)

// ConfigError is a configuration error
type ConfigError struct {
	err string
	msg string
}

// NewConfigError returns a new ConfigError.
// The err argument can be a string or an error.
func NewConfigError(err any, msg string) *ConfigError {
	return &ConfigError{
		err: cast.ToString(err),
		msg: msg,
	}
}

// Error implements the error interface
func (e ConfigError) Error() string {
	return e.err + ": " + e.msg
}

// LogFatal causes a fatal log
func (e ConfigError) LogFatal(log *slog.Logger) {
	utils.FatalError(log, e.msg, errors.New(e.err))
}
