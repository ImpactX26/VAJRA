import pytest

from vajra.config import VajraConfig, ToolConfig, UpstreamConfig
from vajra.taint import TRUSTED, Integrity, Label, Source, TaintStore, UnknownHandleError
from vajra.taint.policy import PolicyEngine, PolicyViolation

WEB = Label(Integrity.UNTRUSTED, frozenset({Source("web", "tool", "fetch")}))


def test_join_is_monotone():
    assert (TRUSTED | WEB) == WEB
    assert (WEB | TRUSTED) == WEB
    assert (TRUSTED | TRUSTED).trusted


def test_store_resolves_whole_and_embedded_tokens():
    store = TaintStore()
    v = store.put(WEB, "payload", structured={"k": 1})

    whole, label = store.resolve(v.token)
    assert whole == "payload" and label == WEB

    embedded, label = store.resolve({"msg": [f"see: {v.token}!"]})
    assert embedded == {"msg": ["see: payload!"]} and label == WEB

    plain, label = store.resolve({"x": "no handles here", "n": 3})
    assert plain == {"x": "no handles here", "n": 3} and label.trusted


def test_unknown_handle_fails_closed():
    with pytest.raises(UnknownHandleError):
        TaintStore().resolve("$vajra:h_" + "0" * 32)


def test_handles_are_distinct():
    store = TaintStore()
    assert store.put(WEB, "a").handle != store.put(WEB, "a").handle


@pytest.fixture
def policy():
    mail = UpstreamConfig(
        "mail",
        "x",
        tools={
            "send_email": ToolConfig(untrusted_args=frozenset({"body"})),
            "status": ToolConfig(allow_tainted_invocation=True),
        },
    )
    calc = UpstreamConfig("calc", "x", output=Integrity.TRUSTED)
    return PolicyEngine(VajraConfig(upstreams={"mail": mail, "calc": calc}))


def test_untrusted_data_blocked_from_trusted_only_args(policy):
    policy.check_call("mail", "send_email", {"to": TRUSTED, "body": WEB}, TRUSTED)
    with pytest.raises(PolicyViolation, match="'to'"):
        policy.check_call("mail", "send_email", {"to": WEB, "body": TRUSTED}, TRUSTED)


def test_tainted_context_blocks_control_flow(policy):
    with pytest.raises(PolicyViolation, match="tainted"):
        policy.check_call("mail", "send_email", {"to": TRUSTED}, WEB)
    # Even when invocation is allowed, planner-written args inherit the context taint.
    with pytest.raises(PolicyViolation, match="'q'"):
        policy.check_call("mail", "status", {"q": TRUSTED}, WEB)
    policy.check_call("mail", "status", {}, WEB)


def test_output_label_joins_inputs(policy):
    assert policy.tool_output_label("calc", "add", "c1", {"a": TRUSTED}, TRUSTED).trusted
    out = policy.tool_output_label("calc", "add", "c1", {"a": WEB}, TRUSTED)
    assert not out.trusted and Source("web", "tool", "fetch") in out.sources
    assert not policy.tool_output_label("mail", "read_inbox", "c2", {}, TRUSTED).trusted
