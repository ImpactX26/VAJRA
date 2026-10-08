import mcp_types as types

from vajra.proxy.upstream import tool_fingerprint
from vajra.sandbox import hidden_characters, inspect_tool


def tool(name="word_count", description="Count words.", schema=None):
    return types.Tool(name=name, description=description, input_schema=schema or {"type": "object", "properties": {}})


def verdict(t, pin=None, taken=()):
    return inspect_tool(t, fingerprint=tool_fingerprint(t), pin=pin, taken=set(taken))


def test_ordinary_tool_is_admitted():
    assert verdict(tool()) is None


def test_pin_mismatch_is_burned_and_matching_pin_admitted():
    t = tool()
    assert verdict(t, pin=tool_fingerprint(t)) is None
    assert "pin mismatch" in verdict(t, pin="sha256:" + "0" * 32)


def test_shadowing_another_servers_tool_is_burned():
    assert "shadowing" in verdict(tool(name="send_email"), taken={"send_email"})
    assert "shadowing" in verdict(tool(name="quarantine"))  # VAJRA's own tool name is reserved


def test_hidden_characters_anywhere_in_the_definition_are_burned():
    assert "U+200B" in verdict(tool(description="Summarize.​"))
    assert "U+202E" in verdict(tool(schema={"type": "object", "properties": {"x‮": {"type": "string"}}}))
    assert hidden_characters("normal text\nwith newline\tand tab") == []


def test_malformed_definitions_are_burned():
    assert verdict(tool(name="bad name!")) == "invalid tool name"
    assert "longer than" in verdict(tool(description="x" * 2000))
    assert verdict(tool(schema={"type": "string"})) == "input schema is not an object"


from vajra.sandbox import sanitize_html  # noqa: E402


def test_content_sandbox_keeps_visible_text_and_burns_hidden_parts():
    html = (
        "<h1>Guide</h1><p>Step one.</p>"
        '<div style="display:none">secret note</div>'
        '<span hidden>also hidden</span><p aria-hidden="true">aria</p>'
        '<p style="font-size:1px">tiny</p><p style="opacity:0">clear</p>'
        "<!-- a comment --><script>var x = 1</script><style>p{}</style>"
        "<p>Step​ two.</p>"
    )
    text, burned = sanitize_html(html)
    assert text == "Guide\nStep one.\nStep two."
    kinds = [b.kind for b in burned]
    assert kinds.count("element styled to be invisible") == 3
    assert "element with the hidden attribute" in kinds and "element marked aria-hidden" in kinds
    assert "HTML comment" in kinds and "<script> block" in kinds and "invisible characters" in kinds
    assert all(word not in text for word in ("secret", "hidden", "aria", "tiny", "clear", "comment", "var x"))


def test_content_sandbox_on_the_demo_page():
    from pathlib import Path

    html = (Path(__file__).parents[1] / "demo/mock_web/setup_guide.html").read_text(encoding="utf-8")
    text, burned = sanitize_html(html)
    assert "acmetools doctor" in text  # the real setup steps survive
    assert len(burned) == 1 and burned[0].kind == "element styled to be invisible"
    assert burned[0].preview and burned[0].preview not in text  # the hidden block is gone from what anyone downstream sees
