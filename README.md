# ⚡ Hermes Telegram Agent

**Production-grade Autonomous Telegram Bot powered by Hermes Agent & high-performance tooling.**

---

## 🌟 Key Features

1. **Silence-By-Default Group Policy**:
   - In groups and supergroups, the bot remains **100% silent** by default.
   - Triggers strictly on:
     - Explicit mentions (`@BotUsername` or `hermes` / `هرمس` / `پرومته`).
     - Direct replies to any message previously sent by the bot.
     - Direct Messages (1-on-1 private chat).
   - Zero blocking API calls on unaddressed messages.

2. **Live Streaming Responses**:
   - Streams tokens progressively to Telegram with rate-limit dampening (`StreamingTokenBuffer`).
   - Time-To-First-Token (TTFT) visual feedback under **0.5s**.

3. **Smart Autonomous Tool Cabinet**:
   - 📊 **Financial & Crypto**: Real-time Bitcoin, Ethereum, Altcoins, Tether & Free-market Dollar/Gold rates.
   - 🌦 **Weather**: Live Open-Meteo weather forecasts for all Iranian and world cities.
   - 🔍 **Web Search**: Real-time Tavily AI search and DuckDuckGo fallback.
   - 📄 **Web Reader**: URL scraper and text extractor.
   - 🧮 **Scientific Calculator**: Safe math and algebraic expression evaluator.
   - 🕒 **Official Time & Calendar**: Tehran official time with Jalali & Gregorian dates.

4. **Lean Context & Sub-Millisecond Fast Paths**:
   - Eliminates schema bloat (only 4–8 tools attached per request instead of 40+ tools).
   - Instant response for `/ping`, `/time`, `/clear`, `/help`.

---

## 📁 Project Structure

```
hermes-telegram-agent/
├── main.py              # Telegram polling application & trigger router
├── agent_engine.py      # Hermes Agent core loop, streaming & context memory
├── config.py            # Pydantic environment configuration loader
├── tools/
│   ├── __init__.py
│   ├── registry.py      # Smart intent-based tool schema selector
│   ├── financial.py     # Crypto and fiat market rates
│   ├── weather.py       # Open-Meteo weather integration
│   ├── search.py        # Web search & webpage scraper
│   └── system.py        # Calendar, math, and diagnostics
├── utils/
│   ├── __init__.py
│   └── formatter.py     # Markdown-to-Telegram HTML parser
├── Dockerfile           # Minimal multi-stage container
├── railway.toml         # Railway deployment descriptor
├── Procfile
├── requirements.txt
└── .gitignore
```

---

## 🚀 Environment Variables

Configure these variables in your deployment environment (e.g. Railway Variables or `.env`):

| Variable | Description | Default |
|---|---|---|
| `TELEGRAM_BOT_TOKEN` | Telegram Bot Token from @BotFather | *(Required)* |
| `ROUTER_BASE_URL` | AI Router / OpenAI compatible API endpoint | `https://api.openai.com/v1` |
| `ROUTER_API_KEY` | API key for LLM provider / 9router | *(Required for AI)* |
| `ROUTER_MODEL` | Target AI Model | `Hermes-3-Llama-3.1-8B` |
| `ADMIN_ID` | Numeric Telegram ID of Supreme Administrator | `0` |
| `TAVILY_API_KEYS` | Optional Tavily search API key | `""` |

---

## 🐳 Docker Deployment

```bash
docker build -t hermes-telegram-agent .
docker run -d --env-file .env --name hermes-bot hermes-telegram-agent
```

---

## 📄 License
MIT License.
