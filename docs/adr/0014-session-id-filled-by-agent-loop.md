# 0014 — The agent loop fills in the session, not the model

**Status:** accepted · 2026-11-26

`kb_search` must read the course KB plus the current learner's uploads, and never another
session's (ADR 0003). If the model passed the session id, a wrong or injected id (a passage could
say "search session X") would read someone else's uploads. Tools therefore take the session as an
ordinary argument named `session_id`, and the agent loop treats that name as reserved: it removes
the argument from the schemas it shows the model, and on every call sets it to the current session,
overwriting any value the model sent. The MCP server trusts its client (our loop) but not the
model. Clients without a session, such as Goose or eval runs, omit it and read the course KB only.
The cost is a convention every client must follow; a client that forwards model arguments
unchanged would expose the argument again, so the MCP server must stay reachable by trusted clients
only (it binds to localhost).
