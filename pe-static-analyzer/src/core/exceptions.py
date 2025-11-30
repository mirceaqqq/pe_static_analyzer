class AnalyzerError(Exception):
    """Generic error raised by the analyzer runtime."""


class ModuleError(AnalyzerError):
    """Raised when an analyzer module fails."""


class ConfigError(AnalyzerError):
    """Raised when config loading/validation fails."""
