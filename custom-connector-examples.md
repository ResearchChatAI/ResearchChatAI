# Custom Connector — Example Configurations

> ⚠️ **Models can be discontinued at any time.** The model IDs in these examples are
> current as of the last update, but providers retire older models on a rolling basis —
> when a model you rely on is discontinued, your study's chat will stop working. Check
> regularly that your chosen model is still available from your provider (e.g. Anthropic's
> [model list](https://docs.anthropic.com/en/docs/about-claude/models)) and update your
> connector to a current model whenever yours is retired.

---

## Validation Rules

| Rule | Detail |
|---|---|
| **HTTPS only** | URLs must use `https://` — plain HTTP is rejected |
| **No local targets** | `localhost`, `127.0.0.1`, `10.*`, `192.168.*`, etc. are blocked (SSRF protection) |
| **Strict JSON** | Keys must be double-quoted, no comments, no trailing commas |
| **Case-sensitive keys** | `temperature`, not `Temperature`; `max_tokens`, not `Max_tokens` |
| **Template syntax** | Use `{{variable}}` for dynamic values (e.g. `{{streamFlag}}`), not `$variable` |
| **Numeric types** | Use `0.9` not `"0.9"` — some APIs reject string-typed numbers |

---

## Claude — No Streaming

Available models: `claude-sonnet-5`, `claude-opus-5-5`, `claude-haiku-4-5`; older but still available: `claude-opus-4-8`, `claude-sonnet-4-6`

> **Notes for the current Claude models**
> - They think before they answer, and the thinking counts towards `max_tokens`. Keep `max_tokens` generous (16000 here); a low value can cut the answer off or leave it empty.
> - Do not add `temperature`, `top_p` or `top_k`: Claude Opus 4.7 and later reject them with an error.

```json
{
  "version": "1",
  "request": {
    "url": "https://api.anthropic.com/v1/messages",
    "method": "POST",
    "auth": {
      "type": "custom",
      "header": "x-api-key",
      "value": "YOUR-ANTHROPIC-API-KEY"
    },
    "headers": {
      "Content-Type": "application/json",
      "anthropic-version": "2023-06-01"
    },
    "timeoutMs": 120000
  },
  "aiPayload": {
    "model": "claude-sonnet-5",
    "system": "{{systemPrompt}}",
    "max_tokens": 16000
  },
  "history": {
    "mode": "array",
    "extractSystem": true,
    "systemParam": "system"
  },
  "response": {
    "resultPath": "$.content[0].text"
  }
}
```

---

## Claude — Streaming

> **Important:** You must also enable the **"Enable Streaming"** toggle in the study settings. If streaming is not enabled, you will get: `Error: The string did not match the expected pattern.`

```json
{
  "version": "1",
  "request": {
    "url": "https://api.anthropic.com/v1/messages",
    "method": "POST",
    "auth": {
      "type": "custom",
      "header": "x-api-key",
      "value": "YOUR-ANTHROPIC-API-KEY"
    },
    "headers": {
      "Content-Type": "application/json",
      "anthropic-version": "2023-06-01",
      "Accept": "text/event-stream"
    },
    "timeoutMs": 120000,
    "stream": true
  },
  "aiPayload": {
    "model": "claude-sonnet-5",
    "system": "{{systemPrompt}}",
    "max_tokens": 16000,
    "stream": true
  },
  "history": {
    "mode": "array",
    "extractSystem": true,
    "systemParam": "system"
  },
  "response": {
    "resultPath": "$.content[0].text",
    "stream": {
      "linePrefix": "data:",
      "doneSignal": "[DONE]",
      "extractors": [
        {
          "filter": { "$.type": "content_block_delta", "$.delta.type": "text_delta" },
          "tokenPath": "$.delta.text"
        },
        {
          "filter": { "$.type": "content_block_delta", "$.delta.type": "output_text_delta" },
          "tokenPath": "$.delta.text"
        },
        {
          "filter": { "$.type": "content_block_delta" },
          "tokenPath": "$.delta.text"
        }
      ]
    }
  }
}
```

---

## Claude — Streaming with Extended Thinking

> **Important:** You must also enable the **"Enable Streaming"** toggle in the study settings. If streaming is not enabled, you will get: `Error: The string did not match the expected pattern.`

Uses `reasoningExtractors` to capture Claude's `thinking_delta` events and display them in a collapsible "Thinking..." block above the response. Untick **"Hide reasoning in chat"** in the study settings, otherwise the block stays hidden.

Available models: `claude-sonnet-5`, `claude-opus-5-5`; older but still available: `claude-opus-4-8`, `claude-sonnet-4-6`. `effort` can be `low`, `medium` or `high`. Claude Haiku 4.5 does not support this configuration.

```json
{
  "version": "1",
  "request": {
    "url": "https://api.anthropic.com/v1/messages",
    "method": "POST",
    "auth": {
      "type": "custom",
      "header": "x-api-key",
      "value": "YOUR-ANTHROPIC-API-KEY"
    },
    "headers": {
      "Content-Type": "application/json",
      "anthropic-version": "2023-06-01",
      "Accept": "text/event-stream"
    },
    "timeoutMs": 120000,
    "stream": true
  },
  "aiPayload": {
    "model": "claude-sonnet-5",
    "system": "{{systemPrompt}}",
    "max_tokens": 16000,
    "thinking": {
      "type": "adaptive",
      "display": "summarized"
    },
    "output_config": {
      "effort": "medium"
    },
    "stream": true
  },
  "history": {
    "mode": "array",
    "extractSystem": true,
    "systemParam": "system"
  },
  "response": {
    "resultPath": "$.content[0].text",
    "reasoningPath": "$.content[0].thinking",
    "stream": {
      "linePrefix": "data:",
      "doneSignal": "[DONE]",
      "extractors": [
        {
          "filter": { "$.type": "content_block_delta", "$.delta.type": "text_delta" },
          "tokenPath": "$.delta.text"
        }
      ],
      "reasoningExtractors": [
        {
          "filter": { "$.type": "content_block_delta", "$.delta.type": "thinking_delta" },
          "tokenPath": "$.delta.thinking"
        }
      ]
    }
  }
}
```

---

## ChatGPT — Streaming

> **Important:** You must also enable the **"Enable Streaming"** toggle in the study settings. If streaming is not enabled, you will get: `Error: The string did not match the expected pattern.`

```json
{
  "version": "1",
  "request": {
    "url": "https://api.openai.com/v1/chat/completions",
    "method": "POST",
    "auth": {
      "type": "bearer",
      "token": "YOUR-OPENAI-API-KEY"
    },
    "headers": {
      "Content-Type": "application/json",
      "Accept": "text/event-stream"
    },
    "timeoutMs": 30000,
    "stream": true
  },
  "aiPayload": {
    "model": "gpt-4o-mini",
    "temperature": 0.7,
    "max_tokens": 1024,
    "stream": true
  },
  "history": {
    "mode": "array",
    "extractSystem": false
  },
  "response": {
    "resultPath": "$.choices[0].message.content",
    "stream": {
      "linePrefix": "data:",
      "doneSignal": "[DONE]",
      "extractors": [
        { "tokenPath": "$.choices[0].delta.content" }
      ]
    }
  }
}
```

---

## Mistral — No Streaming

Available models (fixed versions, so the model does not change on its own): `mistral-small-2603` (Small 4), `mistral-medium-3-5` (Medium 3.5), `mistral-large-2512` (Large 3), `ministral-14b-2512`, `ministral-8b-2512`. The `-latest` aliases (e.g. `mistral-small-latest`) still work, but Mistral moves them to newer models without notice.

```json
{
  "version": "1",
  "request": {
    "url": "https://api.mistral.ai/v1/chat/completions",
    "method": "POST",
    "auth": {
      "type": "bearer",
      "token": "YOUR-MISTRAL-API-KEY"
    },
    "headers": {
      "Content-Type": "application/json"
    },
    "timeoutMs": 30000
  },
  "aiPayload": {
    "model": "mistral-small-2603",
    "temperature": 0.7,
    "max_tokens": 1024
  },
  "history": {
    "mode": "array",
    "extractSystem": false
  },
  "response": {
    "resultPath": "$.choices[0].message.content"
  }
}
```

---

## Mistral — Streaming

> **Important:** You must also enable the **"Enable Streaming"** toggle in the study settings. If streaming is not enabled, you will get: `Error: The string did not match the expected pattern.`

Available models (fixed versions, so the model does not change on its own): `mistral-small-2603` (Small 4), `mistral-medium-3-5` (Medium 3.5), `mistral-large-2512` (Large 3), `ministral-14b-2512`, `ministral-8b-2512`. The `-latest` aliases (e.g. `mistral-small-latest`) still work, but Mistral moves them to newer models without notice.

```json
{
  "version": "1",
  "request": {
    "url": "https://api.mistral.ai/v1/chat/completions",
    "method": "POST",
    "auth": {
      "type": "bearer",
      "token": "YOUR-MISTRAL-API-KEY"
    },
    "headers": {
      "Content-Type": "application/json",
      "Accept": "text/event-stream"
    },
    "timeoutMs": 30000,
    "stream": true
  },
  "aiPayload": {
    "model": "mistral-small-2603",
    "temperature": 0.7,
    "max_tokens": 1024,
    "stream": true
  },
  "history": {
    "mode": "array",
    "extractSystem": false
  },
  "response": {
    "resultPath": "$.choices[0].message.content",
    "stream": {
      "linePrefix": "data:",
      "doneSignal": "[DONE]",
      "extractors": [
        { "tokenPath": "$.choices[0].delta.content" }
      ]
    }
  }
}
```

---

## Mistral — Streaming with Reasoning

> **Important:** You must also enable the **"Enable Streaming"** toggle in the study settings. If streaming is not enabled, you will get: `Error: The string did not match the expected pattern.`

Uses `reasoning_effort: "high"` on `mistral-small-2603` (Small 4) or `mistral-medium-3-5` (Medium 3.5). These are the only Mistral models with reasoning; the Magistral models were retired on July 31, 2026, and other models reject `reasoning_effort` with an error. Untick **"Hide reasoning in chat"** in the study settings to show the reasoning block.

When reasoning is enabled, the response `content` becomes an array with `{type: "thinking", ...}` and `{type: "text", ...}` blocks instead of a plain string.

```json
{
  "version": "1",
  "request": {
    "url": "https://api.mistral.ai/v1/chat/completions",
    "method": "POST",
    "auth": {
      "type": "bearer",
      "token": "YOUR-MISTRAL-API-KEY"
    },
    "headers": {
      "Content-Type": "application/json",
      "Accept": "text/event-stream"
    },
    "timeoutMs": 120000,
    "stream": true
  },
  "aiPayload": {
    "model": "mistral-small-2603",
    "reasoning_effort": "high",
    "temperature": 0.7,
    "max_tokens": 8192,
    "stream": true
  },
  "history": {
    "mode": "array",
    "extractSystem": false
  },
  "response": {
    "resultPath": "$.choices[0].message.content",
    "stream": {
      "linePrefix": "data:",
      "doneSignal": "[DONE]",
      "extractors": [
        { "tokenPath": "$.choices[0].delta.content" }
      ]
    }
  }
}
```

---

## Ollama (OpenAI-compatible) — No Streaming

> **Note:** Ollama typically runs on localhost, which is blocked by SSRF protection.
> To use it, expose Ollama behind an HTTPS reverse proxy on a public/allowed domain.

```json
{
  "version": "1",
  "request": {
    "url": "https://your-ollama-proxy.example.com/v1/chat/completions",
    "method": "POST",
    "auth": {
      "type": "bearer",
      "token": "your-token-here"
    },
    "headers": {
      "Content-Type": "application/json"
    }
  },
  "aiPayload": {
    "model": "mistral",
    "temperature": 0.9,
    "seed": 1106,
    "max_tokens": 1000,
    "stream": false
  },
  "history": {
    "mode": "array"
  },
  "response": {
    "resultPath": "$.choices[0].message.content"
  }
}
```
