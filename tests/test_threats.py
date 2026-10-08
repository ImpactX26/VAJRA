"""Policy coverage for lateral movement, exfiltration and downstream injection (synthetic labels only)."""

import pytest

from vajra.config import ToolConfig, UpstreamConfig, VajraConfig
from vajra.taint import TRUSTED, Integrity, Label, Source
from vajra.taint.policy import PolicyEngine, PolicyViolation


def untrusted(server: str, secret: bool = False) -> Label:
    return Label(Integrity.UNTRUSTED, frozenset({Source(server, "tool", "t")}), secret)


SECRET_TRUSTED = Label(Integrity.TRUSTED, frozenset({Source("files", "tool", "read_file")}), True)


@pytest.fixture
def policy() -> PolicyEngine:
    files = UpstreamConfig("files", "x", tools={
        "read_file": ToolConfig(secret_when={"path": r"^secrets/"}),
        "write_file": ToolConfig(untrusted_args=frozenset({"content"}), accepts_from={"content": frozenset({"files"})}),
    })
    mail = UpstreamConfig("mail", "x", tools={
        "send_email": ToolConfig(
            untrusted_args=frozenset({"body"}), egress=True,
            arg_patterns={"to": r"[A-Za-z0-9._%+-]+@corp\.example"},
        ),
    })
    db = UpstreamConfig("db", "x", tools={
        "lookup_customer": ToolConfig(untrusted_args=frozenset({"customer_id"}), arg_patterns={"customer_id": r"C-\d{6}"}),
    })
    web = UpstreamConfig("web", "x")
    return PolicyEngine(VajraConfig(upstreams={"files": files, "mail": mail, "db": db, "web": web}))


def test_lateral_movement_untrusted_data_cannot_cross_into_other_servers(policy):
    policy.check_call("files", "write_file", {"content": untrusted("files")}, TRUSTED)
    with pytest.raises(PolicyViolation, match="data from web"):
        policy.check_call("files", "write_file", {"content": untrusted("web")}, TRUSTED)


def test_secret_data_never_enters_an_egress_tool(policy):
    with pytest.raises(PolicyViolation, match="secret data"):
        policy.check_call("mail", "send_email", {"to": TRUSTED, "body": untrusted("files", secret=True)}, TRUSTED)
    with pytest.raises(PolicyViolation, match="secret data"):  # even trusted secret data
        policy.check_call("mail", "send_email", {"to": TRUSTED, "body": SECRET_TRUSTED}, TRUSTED)
    # ...and once the planner context is secret, even what the planner types itself
    with pytest.raises(PolicyViolation, match="secret data"):
        policy.check_call("mail", "send_email", {"to": TRUSTED, "body": TRUSTED}, Label(Integrity.TRUSTED, frozenset(), True))
    policy.check_call("mail", "send_email", {"to": TRUSTED, "body": untrusted("files")}, TRUSTED)


def test_secret_label_comes_from_the_source_not_the_content(policy):
    secret = policy.tool_output_label("files", "read_file", "c1", {"path": TRUSTED}, TRUSTED, {"path": "secrets/api_keys.env"})
    normal = policy.tool_output_label("files", "read_file", "c2", {"path": TRUSTED}, TRUSTED, {"path": "invoice.txt"})
    assert secret.secret and not normal.secret
    assert (normal | secret).secret  # secrecy spreads through joins


def test_argument_grammar_rejects_unexpected_shapes(policy):
    policy.check_values("db", "lookup_customer", {"customer_id": "C-004211"})
    for bad in ["C-004211 OR 1", "C-1", "", "C-004211\nC-000001"]:
        with pytest.raises(PolicyViolation, match="allowed format"):
            policy.check_values("db", "lookup_customer", {"customer_id": bad})
    policy.check_values("mail", "send_email", {"to": "alice@corp.example"})
    with pytest.raises(PolicyViolation, match="allowed format"):
        policy.check_values("mail", "send_email", {"to": "someone@other.example"})
