# owasp-skills

Agent Skills that teach AI coding assistants (Claude Code, OpenCode, and any
other tool that supports the `SKILL.md` Agent Skills format) to follow OWASP
security best practices while they write and review code.

Instead of hoping an agent remembers to think about SQL injection or broken
access control, these skills load automatically when the agent's task looks
relevant — writing an auth flow, an API endpoint, an LLM-backed feature,
adding a dependency — and bring in checklists, red flags, and secure/insecure
code examples for the stack you're using.

## Skills included

| Skill | Covers | Load it when you're... |
|---|---|---|
| [`owasp-top10-web`](skills/owasp-top10-web) | OWASP Top 10 Web App Security Risks (2021) | Writing/reviewing general web app code: auth, queries, file access, HTTP handling |
| [`owasp-api-security`](skills/owasp-api-security) | OWASP API Security Top 10 (2023) | Designing/implementing REST or GraphQL endpoints, authorization, rate limiting |
| [`owasp-llm-security`](skills/owasp-llm-security) | OWASP Top 10 for LLM Applications (2025) | Building AI agents, RAG pipelines, MCP tool servers, or anything that calls an LLM |
| [`owasp-asvs-secure-coding`](skills/owasp-asvs-secure-coding) | OWASP ASVS, as a prescriptive dev-time checklist | Implementing auth, sessions, access control, crypto, validation, file upload |
| [`owasp-dependency-secrets`](skills/owasp-dependency-secrets) | Dependency (SCA) and secrets hygiene | Adding/upgrading dependencies, setting up CI, handling API keys/credentials |

Each skill is self-contained: a concise `SKILL.md` (always loaded when
triggered) plus `references/*.md` files with the detailed checklist and
per-stack (Node/TypeScript, Python, Java, Go) secure vs. insecure code
examples, loaded on demand so they don't bloat the agent's context.

## Install

There are three ways to install these skills, from simplest to most flexible.
Pick the first one your tool supports — you don't need more than one.

### Option 1: Claude Code's built-in plugin marketplace (no cloning)

If you're new to this and just use Claude Code, this is the easiest path —
Claude Code fetches the skills straight from GitHub for you, no `git clone`
or shell script needed.

```
/plugin marketplace add glauberportella/owasp-skills
/plugin install owasp-top10-web@owasp-skills
```

(Or run the non-interactive equivalents from your regular terminal:
`claude plugin marketplace add glauberportella/owasp-skills` and
`claude plugin install owasp-top10-web@owasp-skills`.)

Each skill is its own installable plugin — swap `owasp-top10-web` for
`owasp-api-security`, `owasp-llm-security`, `owasp-asvs-secure-coding`, or
`owasp-dependency-secrets`. To install all 5 at once, use the bundle:

```
/plugin install owasp-skills-all@owasp-skills
```

Update later with `/plugin marketplace update owasp-skills`, list what's
installed with `/plugin list`, and remove one with
`/plugin uninstall owasp-top10-web@owasp-skills`. This works because the repo
ships a `.claude-plugin/marketplace.json` — see
[Anthropic's plugin marketplace docs](https://code.claude.com/docs/en/plugin-marketplaces)
if you want to understand how that file works.

*OpenCode does not (yet) have an equivalent built-in "install from GitHub"
command — use Option 2 or 3 below instead.*

### Option 2: `install.sh` (works for both Claude Code and OpenCode)

Skills are plain directories with a `SKILL.md` — no build step. `install.sh`
just symlinks them into the directories your tools already read
(`~/.claude/skills`, `~/.opencode/skills`, or the project-local equivalents),
so a later `git pull` in this repo updates every installation.

**Global install (all skills, for every project):**

```bash
git clone https://github.com/glauberportella/owasp-skills.git ~/.owasp-skills
~/.owasp-skills/install.sh
```

**Per-project install** (writes to `./.claude/skills` and `./.opencode/skills`
in the current directory):

```bash
cd your-project
~/.owasp-skills/install.sh --scope project
```

**Install only specific skills:**

```bash
~/.owasp-skills/install.sh owasp-top10-web owasp-api-security
```

**Options:**

| Flag | Values | Default | Effect |
|---|---|---|---|
| `--scope` | `user`, `project` | `user` | Install to `~/` or to the current directory |
| `--tool` | `all`, `claude`, `opencode` | `all` | Which tool's skill directory to target |
| `--copy` | — | off | Copy files instead of symlinking (no auto-update on `git pull`) |
| `--dest` | a path | — | Override the base directory entirely |

**Uninstall:**

```bash
~/.owasp-skills/uninstall.sh
```

Run with the same `--scope`/`--tool`/`--dest` flags you used to install.
It only removes symlinks that point back into this repo — it never touches
unrelated skills.

### Option 3: Clone and copy manually

For any other `SKILL.md`-compatible tool, or if you'd rather not run a
script: clone the repo and copy (or symlink) whichever `skills/<name>`
folders you want into wherever your tool looks for skills.

```bash
git clone https://github.com/glauberportella/owasp-skills.git
cp -r owasp-skills/skills/owasp-top10-web ~/.claude/skills/
```

### Why does the same install work for Claude Code and OpenCode?

Both tools implement the same `SKILL.md` Agent Skills format and read
overlapping directories (`.claude/skills`, `.opencode/skills`, and
`.agents/skills`, at both the project and user-home level). Options 2 and 3
just place each skill in a directory each tool already reads — no per-tool
adaptation needed.

## Writing/updating a skill

Each skill directory follows the same shape:

```
skills/<skill-name>/
├── SKILL.md              # frontmatter (name, description, license, metadata) + concise checklist
└── references/
    ├── checklist.md      # detailed per-item breakdown, insecure/secure examples
    └── stacks/*.md        # per-language idiomatic secure-code examples
```

`SKILL.md`'s `name` must exactly match the directory name
(`^[a-z0-9]+(-[a-z0-9]+)*$`) and its `description` should be dense with the
keywords an agent would use to decide the skill is relevant — that
description, not the body, is what triggers loading.

## License

MIT — see [LICENSE](LICENSE).
