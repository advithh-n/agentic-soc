# Agentic SOC - AI-Powered Security Operations Center

A full-stack, AI-driven Security Operations Center that automates threat detection, incident investigation, and response using a multi-agent pipeline. 12 Docker microservices, 5 detection modules, 29 rules, 3 AI agents, and a real-time dashboard.

## Architecture

```
                          ┌─────────────────────────────────────────────┐
                          │              INGEST LAYER                   │
                          │   Webhooks (Stripe, Auth, Guardrails,       │
                          │   Langfuse, Recon Scanner)                  │
                          └──────────────────┬──────────────────────────┘
                                             │
                          ┌──────────────────▼──────────────────────────┐
                          │          DETECTION ENGINE                    │
                          │  5 Modules · 29 Rules · MITRE ATT&CK/ATLAS │
                          └──────────────────┬──────────────────────────┘
                                             │
              ┌──────────────────────────────▼──────────────────────────────┐
              │                     AI AGENT PIPELINE                       │
              │                                                            │
              │  Triage Agent ──▶ Investigation Agent ──▶ Critic Agent     │
              │  (classify)       (7-step analysis)       (policy review)  │
              │                          │                      │          │
              │                    MCP Tools                Action         │
              │              (AbuseIPDB, Sploitus,       Executor          │
              │               Neo4j, Wazuh, Clerk,    (auto + human       │
              │               Langfuse, CloudTrail)     approval)          │
              └────────────────────────────────────────────────────────────┘
                                             │
              ┌──────────────────────────────▼──────────────────────────────┐
              │                       DATA LAYER                            │
              │  PostgreSQL+pgvector │ Neo4j Graph │ Redis Stack │ MinIO    │
              │    (17 tables)       │ (25 nodes)  │  (pub/sub)  │ (files)  │
              └─────────────────────────────────────────────────────────────┘
```

## Key Features

### Detection Engine — 5 Modules, 29 Rules
| Module | Rules | Coverage |
|--------|-------|----------|
| Stripe Carding | 5 | Rapid card testing, velocity checks, BIN analysis |
| Auth Anomaly | 5 | Brute force, impossible travel, credential stuffing |
| Infrastructure | 5 | Privilege escalation, config changes, lateral movement |
| AI Agent Monitor | 10 | Prompt injection, jailbreak, tool loops, token abuse, guardrail blocks |
| Recon | 4 | Port drift, new CVEs, certificate expiry, DNS drift |

All rules mapped to MITRE ATT&CK + ATLAS techniques.

### 3-Agent AI Pipeline
- **Triage Agent** — Classifies alerts (true positive / false positive / needs investigation). Uses Claude Haiku for speed, falls back to rule-based if no API key.
- **Investigation Agent** — 7-step analysis: enrichment, blast radius (Neo4j), exploit search (Sploitus), threat actor attribution, root cause mapping, response action generation. Uses Claude Sonnet.
- **Critic Agent** — Policy-based review of proposed actions. Risk classification (auto/high/critical). Evidence threshold enforcement.
- **Action Executor** — Auto-executes approved low-risk actions. Queues high/critical for human approval. 5 mock adapters, 13 action types.

### MCP Tool Server — 7 Integrations, 15 Tools
| Integration | Status | Tools |
|-------------|--------|-------|
| Neo4j | Live | Graph queries, blast radius, threat actor profiles, IOC linking |
| AbuseIPDB | Live (API key required) | IP reputation lookup, Redis-cached |
| Sploitus | Live | CVE/exploit search, Redis-cached |
| AWS CloudTrail | Mock adapter | Event queries, IAM activity (swap to boto3 for production) |
| Wazuh | Mock adapter | Host alerts, agent health (swap to real Wazuh API) |
| Clerk | Mock adapter | Session queries, user profiles (swap to Clerk SDK) |
| Langfuse | Mock adapter | LLM trace queries, generation details |

Mock adapters return realistic data and are designed as drop-in replacements — configure the env var and the real API is used automatically.

### Dashboard — Next.js 15, 13 Routes
- **SOC Overview** — Real-time alert feed via WebSocket
- **Alerts** — Filterable list, detail view, CSV export
- **Incidents** — Correlated alerts, blast radius, root cause, linked actions
- **Approvals** — Human approval queue for high-risk response actions
- **Playbooks** — 4 automated response workflows with run-on-incident modal
- **AI Agents** — Agent status, pipeline logs, execution traces
- **Analytics** — 4 tabs: Overview KPIs, MITRE ATT&CK heatmap, Agent Performance, Response Actions
- **System Health** — Real-time service monitoring, auto-refresh
- **Audit Log** — Tamper-evident log with JSON details, chain verification
- **Settings** — User management, module config, API keys, Slack notifications

### Phase 7 Features (PentAGI Integration)
- **Exploit Search** — Sploitus integration in investigation pipeline
- **Agent Memory** — 384-dim keyword embeddings, recall similar past investigations
- **Chain Summarization** — Claude Haiku for context compression in long investigations
- **Langfuse Observability** — Every LLM call logged with input/output/tokens/latency
- **PDF Reports** — Incident report generation (fpdf2), stored in MinIO, downloadable from dashboard
- **Threat Actor Knowledge Graph** — Neo4j with seeded actors (FIN7, Lazarus, CardingRing), campaigns, IOCs
- **Detection Validation** — 29-rule test suite with MITRE coverage matrix and gap analysis

### E2E Validated Results
| Metric | Value |
|--------|-------|
| Detection rate | 94%+ (22/29 rules tested across 6 scenarios) |
| Alerts triaged | 110 |
| Escalated to investigation | 90 |
| Critic reviews | 90 |
| Response actions generated | 664 (569 auto-executed, 77 pending human, 0 failed) |
| Execution traces | 8,223 |
| Mean Time to Detect (MTTD) | 202.8 seconds |

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.11, FastAPI, asyncpg, Pydantic v2 |
| Frontend | Next.js 15, React 19, TypeScript, Tailwind CSS |
| Databases | PostgreSQL 16 + pgvector, Neo4j 5, Redis Stack, MinIO |
| AI | Anthropic Claude (Sonnet + Haiku), LLM-as-judge |
| Infrastructure | Docker Compose, Traefik v3, Prometheus |
| Observability | Langfuse, structlog, execution tracing |

## Quick Start

### Prerequisites
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (4GB+ RAM allocated)
- [Git](https://git-scm.com/)

### 1. Clone and configure

```bash
git clone https://github.com/advithh-n/agentic-soc.git
cd agentic-soc

# Copy environment template
cp .env.example .env
```

Edit `.env` and set at minimum these passwords (replace `CHANGE_ME` values):

```bash
PG_PASS=your_postgres_password
NEO4J_PASS=your_neo4j_password
REDIS_PASS=your_redis_password
MINIO_PASS=your_minio_password
JWT_SECRET=your_jwt_secret_run_openssl_rand_hex_64
N8N_PASS=your_n8n_password
```

Optional (enables real API enrichment):
```bash
ANTHROPIC_API_KEY=sk-ant-...     # Enables LLM-powered agent reasoning
ABUSEIPDB_API_KEY=...            # Enables live IP reputation lookups
```

The system works fully without these — agents fall back to rule-based mode, MCP tools return mock data.

### 2. Start all services

```bash
docker compose up -d
```

Wait ~60 seconds for all 12 containers to become healthy:

```bash
docker compose ps
```

All services should show `Up` or `healthy`.

### 3. Access the dashboard

Open **http://localhost:3000** in your browser.

**Login credentials:**
| Field | Value |
|-------|-------|
| Email | `admin@heya.au` |
| Password | `changeme` |
| Tenant | `heya` |

### 4. Run the attack simulation

Open a terminal and run the E2E test to populate the dashboard with real detection data:

```bash
# From the project root
python simulator/e2e_test.py
```

Or on Windows:
```bash
py simulator/e2e_test.py
```

This launches 6 attack scenarios (carding, brute force, IAM escalation, AI agent attacks, recon, false positives). Watch the dashboard — alerts will stream in real-time via WebSocket.

### 5. Explore

After the E2E test completes (~2-3 minutes):
- **Alerts** — 110+ alerts with severity, MITRE technique, triage status
- **Incidents** — Correlated incidents with blast radius and root cause
- **Approvals** — Pending human approval actions
- **Analytics** — MITRE ATT&CK heatmap, MTTD/MTTR, agent performance
- **Playbooks** — Run automated response workflows on incidents

## Service Ports

| Service | Port | URL |
|---------|------|-----|
| Dashboard | 3000 | http://localhost:3000 |
| API | 8050 | http://localhost:8050/api/v1/health |
| PostgreSQL | 5432 | — |
| Neo4j Browser | 7474 | http://localhost:7474 |
| Redis Insight | 8001 | http://localhost:8001 |
| MinIO Console | 9001 | http://localhost:9001 |
| n8n | 5678 | http://localhost:5678 |
| Traefik Dashboard | 8080 | http://localhost:8080 |
| Prometheus | 9090 | http://localhost:9090 |

## Project Structure

```
agentic-soc/
├── api/                  # FastAPI backend
│   ├── app/routes/       #   13 route modules (56+ endpoints)
│   ├── app/auth/         #   JWT + RBAC
│   └── app/services/     #   PDF report generator
├── agents/               # AI agent runtime
│   └── runtime/          #   triage, investigation, critic agents
│                         #   memory, observability, execution tracer
├── modules/              # Detection engine
│   ├── stripe_carding/   #   5 rules
│   ├── auth_anomaly/     #   5 rules
│   ├── infrastructure/   #   5 rules
│   ├── ai_agent_monitor/ #   10 rules
│   └── recon/            #   4 rules
├── mcp-servers/          # MCP tool integrations
│   ├── neo4j_tools.py    #   Graph queries + threat actor KG
│   ├── abuseipdb_tools.py#   IP reputation (live API)
│   ├── sploitus_tools.py #   Exploit search (live API)
│   ├── aws_tools.py      #   CloudTrail (mock)
│   ├── wazuh_tools.py    #   Host alerts (mock)
│   ├── clerk_tools.py    #   Auth sessions (mock)
│   └── langfuse_tools.py #   LLM traces (mock)
├── dashboard/            # Next.js 15 frontend (13 routes)
├── simulator/            # Attack simulation + E2E tests
│   ├── e2e_test.py       #   Full pipeline validation
│   ├── validation_mode.py#   29-rule detection coverage test
│   └── scenarios/        #   6 attack scenarios
├── db/                   # Database migrations and seeds
├── monitoring/           # Prometheus config
├── traefik/              # Reverse proxy config
├── docker-compose.yml    # 12 services
└── .env.example          # Environment template
```

## Detection Validation

Run the detection coverage test to verify all 29 rules fire correctly:

```bash
py simulator/validation_mode.py
```

Outputs a MITRE ATT&CK + ATLAS coverage matrix showing which techniques are covered, partially covered, or have gaps.

## API Documentation

With the API running, visit **http://localhost:8050/docs** for the auto-generated Swagger UI with all 56+ endpoints documented.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Author

**Advith Niranjan** - Master of Cybersecurity, RMIT University

- GitHub: [github.com/advithh-n](https://github.com/advithh-n)
- LinkedIn: [linkedin.com/in/advith-niranjan](https://linkedin.com/in/advith-niranjan)
