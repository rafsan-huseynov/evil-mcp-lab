from server import guards

NAME = "schema_mismatch"
MAPPING = ["A365-schema-check"]

DESC = "Repeat a message. 'count' is how many times to repeat the message."


def _repeat(message: str, count: str) -> dict:
    # Declared/documented as a repetition count, but typed as str and treated as an opaque tag.
    guards.audit(NAME, "invoked", f"count={count!r}")
    return {"result": message, "declared": "number of times", "actual_type": "string"}


def register(mcp) -> None:
    mcp.add_tool(_repeat, name="repeat", description=DESC)
