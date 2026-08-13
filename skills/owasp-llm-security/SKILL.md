---
name: owasp-llm-security
description: Use when building applications that call LLMs, AI agents, chatbots, RAG (retrieval-augmented generation) pipelines, or MCP tool servers/clients. Invoke for prompt injection and jailbreaks, insecure/unsanitized LLM output handling, excessive agent agency and over-permissioned tool/function calling, system prompt leakage, sensitive information disclosure through prompts or completions, RAG/vector store data exposure and embedding weaknesses, model/data supply chain risk (untrusted models, plugins, fine-tunes, training data poisoning), misinformation and hallucination handling, and unbounded token/cost/resource consumption (denial of wallet). Covers the OWASP Top 10 for LLM Applications (2025), LLM01-LLM10.
license: MIT
metadata:
  domain: security
  version: "1.0.0"
  triggers: LLM security, prompt injection, jailbreak, AI agent security, RAG security, vector store security, MCP security, tool calling, function calling, system prompt leakage, hallucination, excessive agency, denial of wallet, model supply chain, data poisoning, sensitive information disclosure, output handling, OWASP LLM Top 10
  related-skills: owasp-top10-web, owasp-api-security, owasp-asvs-secure-coding, owasp-dependency-secrets
---

# OWASP LLM Security

The OWASP Top 10 for LLM Applications (2025) catalogs the risks specific to building software that calls, embeds, or is powered by large language models: LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM03 Supply Chain, LLM04 Data and Model Poisoning, LLM05 Improper Output Handling, LLM06 Excessive Agency, LLM07 System Prompt Leakage, LLM08 Vector and Embedding Weaknesses, LLM09 Misinformation, LLM10 Unbounded Consumption.

These risks are distinct from classic web/API vulnerabilities (OWASP Top 10, API Security Top 10) because the attack surface is different in kind:

- **Untrusted natural language is an input channel.** Any text a model reads — user messages, retrieved documents, tool results, web pages, file contents — can carry instructions that compete with the developer's own instructions. There is no syntax boundary between "data" and "code" the way there is in SQL or HTML.
- **Agentic tool-calling turns a text-generation bug into an action-execution bug.** When an LLM can call functions, hit APIs, run code, or touch a filesystem, a successful injection or hallucination can directly cause a delete, a payment, a data exfiltration, or an SSRF — not just a bad string on screen.
- **Output is non-deterministic and semi-trusted.** The same prompt can produce different completions, and a "helpful" model will often try to satisfy an injected instruction rather than refuse it. Output must be validated and constrained the same way any other untrusted input would be, before it is rendered, executed, or acted upon.

## When to Use This Skill

Use this skill whenever the code being written or reviewed:

- Builds an AI agent, chatbot, or assistant (single-agent or multi-agent/orchestrated).
- Implements a RAG (retrieval-augmented generation) pipeline: chunking, embedding, vector store, retrieval, or context assembly.
- Implements or consumes an MCP (Model Context Protocol) server or client, or any tool/function-calling interface for an LLM.
- Constructs prompt templates, system prompts, or assembles context that mixes trusted instructions with untrusted user/document/tool content.
- Gives an LLM the ability to call functions, invoke tools, run code, query databases, or take actions with real-world side effects.
- Handles any text that a user supplies which eventually reaches a model (chat input, uploaded documents, form fields summarized by an LLM, etc.), or handles model output that will be rendered, logged, stored, or executed.
- Selects, fine-tunes, or integrates third-party models, embeddings, plugins, or LLM SDKs (supply chain considerations).

## Checklist (LLM01-LLM10)

| # | Risk | Red flag while coding |
|---|------|------------------------|
| LLM01 | Prompt Injection | User/document/tool text concatenated straight into the system prompt with no delimiter or instruction hierarchy |
| LLM02 | Sensitive Information Disclosure | Secrets, PII, or internal data placed in prompts, or full prompts/completions logged/cached without redaction |
| LLM03 | Supply Chain | Unpinned/unverified model weights, LoRA adapters, plugins, or LLM-related packages pulled from untrusted sources |
| LLM04 | Data and Model Poisoning | Training/fine-tuning/RAG-ingested data accepted from untrusted or unvalidated sources with no provenance checks |
| LLM05 | Improper Output Handling | Model output passed to `eval`, a shell, a DB query, or `innerHTML`/raw HTML render without validation or encoding |
| LLM06 | Excessive Agency | Agent/tool has broad credentials (e.g. full DB admin, unrestricted shell) or acts destructively with no human approval |
| LLM07 | System Prompt Leakage | System prompt contains secrets/business logic and relies on the model to "just not repeat it" as the only defense |
| LLM08 | Vector and Embedding Weaknesses | Vector store has no per-tenant/per-document access control; retrieved chunks bypass the caller's authorization |
| LLM09 | Misinformation | Model output presented as fact with no confidence signal, citation, or human review for high-stakes decisions |
| LLM10 | Unbounded Consumption | No per-request/session limits on tokens, context size, output length, concurrent calls, or spend |

## Reference Guide

| Topic | Reference | Load When |
|-------|-----------|-----------|
| Full checklist with detect/insecure/secure patterns | `references/checklist.md` | Reviewing or writing code against any LLM01-LLM10 risk; need concrete before/after examples |
| Python LLM SDKs | `references/stacks/python-llm-sdks.md` | Working with OpenAI/Anthropic Python SDKs, LangChain/LangGraph, Pydantic output validation |
| Node.js/TypeScript LLM SDKs | `references/stacks/nodejs-typescript-llm-sdks.md` | Working with Vercel AI SDK, LangChain.js, OpenAI/Anthropic Node SDKs, Zod output validation |
| MCP tool servers | `references/stacks/mcp-tool-servers.md` | Building or consuming an MCP server/client, designing tool schemas, agent tool permissions |

## Constraints

### MUST DO
- MUST treat all LLM output as untrusted before rendering as HTML, executing as code, or using in a SQL/shell/file-path context — apply the same escaping/validation as any other user input (LLM05).
- MUST validate model-produced structured output (JSON/tool-call arguments) against a strict schema (e.g. Pydantic, Zod) before acting on it (LLM05, LLM06).
- MUST scope each agent/tool's credentials and permissions to the minimum required for its specific task, not a shared broad credential (LLM06).
- MUST require explicit human confirmation before an agent performs a destructive or irreversible action (delete, payment, send, deploy) (LLM06).
- MUST separate trusted system instructions from untrusted content using clear delimiters and re-assert instruction priority after any inserted content (LLM01).
- MUST enforce per-request and per-session limits on tokens, context length, output length, iteration/loop counts, and concurrent calls, plus cost alerting (LLM10).
- MUST apply access control on the vector store/retriever itself (per-tenant, per-user, per-document), not just on the application layer above it (LLM08).
- MUST pin and verify the provenance of models, embeddings, adapters, and LLM-related packages before use (LLM03).
- MUST label or flag AI-generated content that informs consequential decisions, and require human review for high-stakes outputs (LLM09).

### MUST NOT DO
- MUST NOT concatenate untrusted user/document/tool content directly into the system prompt without a clear delimiter and instruction-hierarchy defense (LLM01).
- MUST NOT log or cache full prompts/completions that may contain PII or secrets by default; redact before persisting (LLM02).
- MUST NOT give an agent tool/function-calling permissions broader than the specific task requires — no shared "god credential" across agents or tools (LLM06).
- MUST NOT rely on the system prompt alone (with no output-side or access-control defense) to protect secrets or business rules — assume it can be extracted (LLM07).
- MUST NOT ingest training, fine-tuning, or RAG source data from untrusted origins without validation, sanitization, and provenance tracking (LLM04).
- MUST NOT let an agent chain tool calls indefinitely with no step/iteration/spend cap — this enables both runaway cost and runaway agency (LLM06, LLM10).
- MUST NOT feed raw, unsanitized tool/API/browsing results back into the model context without treating them as untrusted input subject to the same injection defenses as user text (LLM01).

## Knowledge Reference

OWASP Top 10 for LLM Applications 2025, MITRE ATLAS, NIST AI RMF, prompt injection, jailbreak taxonomies, indirect prompt injection, RAG poisoning, tool/function-calling schemas, MCP (Model Context Protocol).
