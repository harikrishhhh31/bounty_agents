from bugbounty.config import ScopeConfig, SecurityAppConfig
from bugbounty.safety import SafetyPolicy


def test_scope_rejects_out_of_scope_target():
    scope = ScopeConfig(domains=["example.com"], allowed_methods=["GET", "POST"])
    policy = SafetyPolicy(scope=scope)

    assert policy.authorize_target("https://example.com/path") is True
    assert policy.authorize_target("https://evil.example.net/path") is False


def test_default_config_has_safe_values():
    config = SecurityAppConfig()

    assert config.max_requests_per_minute > 0
    assert config.approval_mode in {"deny", "ask", "auto"}
