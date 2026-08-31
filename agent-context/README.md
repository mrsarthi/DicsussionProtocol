# agent-context

Files written for whoever — or whatever — picks this project up next.

Not documentation of the code. `specs/` is normative, `HOW_TO_USE.md` is
the guide, and `PROGRESS.md` is the chronological record. These two are
the layer above all of that: what to know before touching any of it.

| File | What it is |
| :--- | :--- |
| [`PROJECT_KNOWLEDGE.md`](PROJECT_KNOWLEDGE.md) | The working understanding built over the whole project — the decisions, the alternatives that were rejected and why, the bugs worth generalising from, and how work gets done here. **Read this first.** |
| [`AGENT_INSTRUCTIONS.md`](AGENT_INSTRUCTIONS.md) | The master prompt the project was built against: role, philosophy, stack and architectural specification. |

## Why these are in the repository

They were kept in a gitignored folder alongside app-specific strategy
notes, which is the right place for notes about a *different* project and
the wrong place for the only written record of why this one is shaped as
it is. That record is worth as much as the specs and is no more sensitive
than they are: every limitation it names is already stated in the README,
the release notes or the RFCs.

What stays out of the repository stays out for a reason —
`docs/SECURITY_BACKLOG.md` carries severities and effort estimates for
live findings, which is a map of where to push before the fixes land.
Neither file here is that.

## Keeping them true

`PROJECT_KNOWLEDGE.md` states the version it was written at, and closes
by saying that where it and the code disagree, the code is right and the
file is a bug. Treat it that way: if you find it stale, fixing it is part
of the work, not a separate errand.
