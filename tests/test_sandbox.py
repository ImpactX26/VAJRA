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
