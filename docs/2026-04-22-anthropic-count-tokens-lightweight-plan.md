# Anthropic Count Tokens Lightweight Semantics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `/v1/messages/count_tokens` reflect Claude Code's logical Anthropic input size rather than the inflated full Kiro payload size.

**Architecture:** Keep the endpoint, but change its counting semantics. Instead of building a full Kiro payload and tokenizing the serialized JSON, compute tokens directly from the incoming Anthropic request's `messages`, `system`, and user-provided `tools`. Exclude gateway-injected `web_search`, fake reasoning prompt injection, truncation recovery additions, and other Kiro wrapper metadata.

**Tech Stack:** Python, FastAPI, Pydantic, pytest, tiktoken

---

## File map

- Modify: `kiro/routes_anthropic.py` — change `count_tokens_endpoint()` semantics to count logical Anthropic input
- Reuse: `kiro/tokenizer.py` — use existing token counting helpers
- Test: `tests/unit/test_routes_anthropic.py` — add/adjust endpoint behavior tests

### Task 1: Prove current count is inflated

**Files:**
- Modify: `tests/unit/test_routes_anthropic.py`
- Test: `tests/unit/test_routes_anthropic.py`

- [ ] **Step 1: Write the failing test**

Add a test asserting a trivial user message should not return a massively inflated token count.

```python
def test_count_tokens_for_simple_message_stays_reasonable(self, test_client, valid_proxy_api_key):
    response = test_client.post(
        "/v1/messages/count_tokens",
        headers={"x-api-key": valid_proxy_api_key},
        json={
            "model": "claude-sonnet-4-5",
            "max_tokens": 64,
            "messages": [{"role": "user", "content": "hello"}],
        },
    )

    assert response.status_code == 200
    assert response.json()["input_tokens"] < 200
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python -m pytest tests/unit/test_routes_anthropic.py -k reasonable -q`
Expected: FAIL because the current implementation counts the full Kiro payload and returns a much larger number.

- [ ] **Step 3: Write minimal implementation**

In `kiro/routes_anthropic.py`, replace payload-JSON counting with logical Anthropic request counting using:
- `count_message_tokens(...)`
- `count_tools_tokens(...)`
- `count_system_tokens(...)`

Pseudo-shape:

```python
messages_for_tokenizer = [msg.model_dump() for msg in request_data.messages]
user_tools = request_data.tools or []
user_tools_for_tokenizer = [tool.model_dump() for tool in user_tools if getattr(tool, "type", None) is None]
system_for_tokenizer = request_data.system
input_tokens = (
    count_message_tokens(messages_for_tokenizer, apply_claude_correction=False)
    + count_tools_tokens(user_tools_for_tokenizer, apply_claude_correction=False)
    + count_system_tokens(system_for_tokenizer, apply_claude_correction=False)
)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python -m pytest tests/unit/test_routes_anthropic.py -k reasonable -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tests/unit/test_routes_anthropic.py kiro/routes_anthropic.py
git commit -m "fix: use Anthropic input semantics for count_tokens"
```

### Task 2: Prove injected web_search is excluded

**Files:**
- Modify: `tests/unit/test_routes_anthropic.py`
- Test: `tests/unit/test_routes_anthropic.py`

- [ ] **Step 1: Write the failing test**

Add a test that compares a basic request with and without gateway auto-injection enabled, and asserts the endpoint only counts user-provided tools.

```python
def test_count_tokens_excludes_auto_injected_web_search(self, test_client, valid_proxy_api_key, monkeypatch):
    monkeypatch.setattr("kiro.routes_anthropic.WEB_SEARCH_ENABLED", True)

    response = test_client.post(
        "/v1/messages/count_tokens",
        headers={"x-api-key": valid_proxy_api_key},
        json={
            "model": "claude-sonnet-4-5",
            "max_tokens": 64,
            "messages": [{"role": "user", "content": "hello"}],
        },
    )

    assert response.status_code == 200
    assert response.json()["input_tokens"] < 200
```

- [ ] **Step 2: Run test to verify it fails (if still counting injected tool)**

Run: `./.venv/bin/python -m pytest tests/unit/test_routes_anthropic.py -k auto_injected_web_search -q`
Expected: FAIL if the implementation still includes auto-injected tool cost.

- [ ] **Step 3: Write minimal implementation**

Ensure `count_tokens_endpoint()` counts only tools from the original request and does not run or depend on the route's auto-injection branch.

```python
user_tools = request_data.tools or []
user_tools_for_tokenizer = [
    tool.model_dump() for tool in user_tools
    if getattr(tool, "type", None) is None
]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python -m pytest tests/unit/test_routes_anthropic.py -k auto_injected_web_search -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tests/unit/test_routes_anthropic.py kiro/routes_anthropic.py
git commit -m "fix: exclude auto-injected tools from count_tokens"
```

### Task 3: Prove user-provided tools are still counted

**Files:**
- Modify: `tests/unit/test_routes_anthropic.py`
- Test: `tests/unit/test_routes_anthropic.py`

- [ ] **Step 1: Write the failing test**

Add a test comparing the token count of a plain request versus the same request with a user-supplied tool.

```python
def test_count_tokens_includes_user_provided_tools(self, test_client, valid_proxy_api_key):
    base = test_client.post(
        "/v1/messages/count_tokens",
        headers={"x-api-key": valid_proxy_api_key},
        json={
            "model": "claude-sonnet-4-5",
            "max_tokens": 64,
            "messages": [{"role": "user", "content": "hello"}],
        },
    )
    with_tool = test_client.post(
        "/v1/messages/count_tokens",
        headers={"x-api-key": valid_proxy_api_key},
        json={
            "model": "claude-sonnet-4-5",
            "max_tokens": 64,
            "messages": [{"role": "user", "content": "hello"}],
            "tools": [{
                "name": "lookup",
                "description": "Look something up",
                "input_schema": {"type": "object", "properties": {"q": {"type": "string"}}, "required": ["q"]}
            }],
        },
    )

    assert with_tool.json()["input_tokens"] > base.json()["input_tokens"]
```

- [ ] **Step 2: Run test to verify it fails if tools were accidentally excluded**

Run: `./.venv/bin/python -m pytest tests/unit/test_routes_anthropic.py -k user_provided_tools -q`
Expected: FAIL if the implementation omits user tools entirely.

- [ ] **Step 3: Write minimal implementation**

Keep counting user-defined tools via `count_tools_tokens(...)`, but do not include server-side native tools or gateway-injected tools.

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python -m pytest tests/unit/test_routes_anthropic.py -k user_provided_tools -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tests/unit/test_routes_anthropic.py kiro/routes_anthropic.py
git commit -m "test: cover lightweight Anthropic count_tokens semantics"
```

### Task 4: Run focused verification and redeploy

**Files:**
- Modify: none unless tests fail
- Test: `tests/unit/test_routes_anthropic.py`, `tests/unit/test_tokenizer.py`

- [ ] **Step 1: Run focused test suite**

Run: `./.venv/bin/python -m pytest tests/unit/test_routes_anthropic.py tests/unit/test_tokenizer.py -q`
Expected: PASS

- [ ] **Step 2: Rebuild and restart the local container**

Run: `docker compose -f docker-compose.yml -f docker-compose.local.yml up -d --build`
Expected: container recreated successfully

- [ ] **Step 3: Verify runtime behavior**

Run: `python3 - <<'PY'
import json, urllib.request
req = urllib.request.Request(
    'http://127.0.0.1:8000/v1/messages/count_tokens?beta=true',
    data=json.dumps({
        'model': 'claude-haiku-4-5-20251001',
        'max_tokens': 16,
        'messages': [{'role': 'user', 'content': 'hello'}]
    }).encode(),
    headers={'content-type': 'application/json', 'x-api-key': 'kiro-gateway-penguin-2026'},
    method='POST'
)
with urllib.request.urlopen(req, timeout=10) as r:
    print(r.status)
    print(r.read().decode())
PY`
Expected: `200` with a materially smaller `input_tokens` than the current ~462-566 range

- [ ] **Step 4: Commit**

No commit unless a final cleanup change is needed.

## Self-review

- Scope is limited to Anthropic count_tokens semantics only.
- Tests explicitly cover the three approved design requirements: smaller logical counts, exclusion of auto-injected web_search, inclusion of user-provided tools.
- No placeholder steps remain.
- Implementation remains within existing files and reuses existing tokenizer helpers.
