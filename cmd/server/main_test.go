package main

import (
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/terrpan/polly/internal/config"
)

// MainTestSuite provides structured tests for the main package without starting the real server.
type MainTestSuite struct {
	suite.Suite
	originalConfig *config.Config
}

func (s *MainTestSuite) SetupTest() {
	// Preserve original config so we can restore after each test to avoid cross-test pollution
	s.originalConfig = config.AppConfig
}

func (s *MainTestSuite) TearDownTest() {
	config.AppConfig = s.originalConfig
}

// Test that init() populated AppConfig with at least the default values.
func (s *MainTestSuite) TestInitPopulatesConfig() {
	s.Require().NotNil(config.AppConfig, "AppConfig should be initialized by init()")
	s.Greater(config.AppConfig.Port, 0, "Port should be set to a positive value")
	s.NotEmpty(config.AppConfig.Version, "Version should not be empty")
}

// Exercise run() error path (no GitHub auth configured) to cover early lifecycle logic without hanging.
func (s *MainTestSuite) TestRun_ReturnsErrorWithoutAuth() {
	// Disable OTLP to avoid setting up telemetry exporters in unit tests
	s.T().Setenv("POLLY_OTLP_ENABLE_OTLP", "false")
	// Re-initialize config to pick up env change
	err := config.InitConfig()
	s.Require().NoError(err)

	runErr := run()
	s.Error(runErr, "run() should error when no GitHub authentication is configured")
	s.Contains(
		runErr.Error(),
		"initialize application container",
		"Error should wrap container init failure",
	)
}

// Sanity check build info values are wired through (gives coverage on GetBuildInfo usage path).
func (s *MainTestSuite) TestBuildInfoAccessible() {
	version, commit, buildTime := config.GetBuildInfo()
	s.IsType("", version)
	s.IsType("", commit)
	s.IsType("", buildTime)
	s.NotEmpty(config.AppConfig.Version)
}

// Ensure fields main() logs are available (does not execute main()).
func (s *MainTestSuite) TestLoggedConfigFieldsAvailable() {
	s.Require().NotNil(config.AppConfig)
	s.NotEmpty(config.AppConfig.Version)
	s.IsType(true, config.AppConfig.OTLP.EnableOTLP)
	s.NotEmpty(config.AppConfig.BuildTime)
}

func TestMainSuite(t *testing.T) {
	suite.Run(t, new(MainTestSuite))
}

// NOTE: A full success-path run() test would require controllable server shutdown.
// To add that later, consider introducing an injectable server factory in main.go.
