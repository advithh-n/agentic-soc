# Agentic SOC - AI-Powered Security Operations Center

A full-stack, AI-driven Security Operations Center (SOC) that automates threat detection, incident investigation, and response using a multi-agent pipeline. Built with Docker microservices, FastAPI, Next.js, and Python.

## Architecture

**12 Docker microservices** working together:

```
Ingest -> Detection Modules -> Triage Agent -> Investigation Agent -> Critic Agent -> Action Executor
                                    |                   |                  |               |
                                PostgreSQL          Neo4j Graph        Redis Queue      Mock Adapters
                                (17 tables)        (25 node types)     (pub/sub)       (5 adapters)
```

## Key Features

### Detection Engine
- **4 detection modules** with **21 rules** covering:
  - Stripe carding fraud (5 rules)
  - Authentication anomalies (4 rules)
  - Infrastructure threats (3 rules)
  - AI agent monitoring (9 rules)
- MITRE ATT&CK + ATLAS technique mapping

### 3-Agent AI Pipeline
- **Triage Agent** - Classifies and prioritizes incoming alerts
- **Investigation Agent** - 7-step investigation with root cause analysis and response action generation
- **Critic Agent** - Policy-based review of investigation findings and proposed actions
- **Action Executor** - Auto-executes approved actions, queues human-approval items

### E2E Validated Results
- **94% detection rate** (17/18 rules triggered)
- 110 alerts triaged, 90 escalated, 90 investigations, 90 critic reviews
- 664 response actions (569 auto-executed, 77 pending human approval, 0 failed)
- 8,223 execution traces
- Mean Time to Detect (MTTD): 202.8 seconds

### Data Layer
- **PostgreSQL + pgvector** - 17 tables for alerts, incidents, actions, audit logs
- **Neo4j** - Graph database with 25 node types for threat intelligence and relationship mapping
- **Redis Stack** - Real-time pub/sub for WebSocket live feeds, alert queuing, and caching
- **MinIO** - S3-compatible object storage for evidence files

### Dashboard (Next.js 15 + React 19)
- 12 routes: Alerts, Incidents, Analytics, Health, Settings, Audit Log, and more
- Real-time WebSocket live alert feed
- MITRE ATT&CK heatmap with technique hit counts
- Analytics with KPIs: MTTD, MTTR, detection rates, agent performance
- Settings: User CRUD, module config, API key management, Slack notifications
- Dark SOC theme with Tailwind CSS

### API (FastAPI)
- JWT authentication with RBAC (role-based access control)
- 12 route modules: alerts, auth, health, ingest, incidents, actions, admin, ai_agents, traces, playbooks, analytics, websockets
- Streaming CSV export, incident report generation
- Admin endpoints for user management, module configuration, API keys, notifications

### Response Automation
- 5 mock adapters (Traefik, Stripe, Auth, Infrastructure, Notification) with 13 action types
- PlaybookEngine with 4 built-in playbooks
- Post-critic hook: auto-approved actions execute immediately
- Severity-based fallback ensures high/critical alerts always generate actions

### MCP Server
- Model Context Protocol server with Neo4j, AbuseIPDB (Redis-cached), and AWS CloudTrail integrations

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python, FastAPI, asyncpg, asyncio |
| Frontend | Next.js 15, React 19, TypeScript, Tailwind CSS |
| Databases | PostgreSQL + pgvector, Neo4j, Redis Stack, MinIO |
| Infrastructure | Docker, Docker Compose, Traefik, Prometheus |
| AI/ML | Anthropic Claude API, LLM-as-judge evaluation |
| Automation | n8n, custom Python agents |

## Quick Start

### Prerequisites
- Docker Desktop
- Git

### Setup

```bash
# Clone the repo
git clone https://github.com/advithh-n/agentic-soc.git
cd agentic-soc

# Copy environment config
cp .env.example .env
# Edit .env with your credentials

# Start all services
docker compose up -d

# Access the dashboard
open http://localhost:3000
```

### Default Login
- Email: `admin@heya.au`
- Password: `changeme`
- Tenant: `heya`

## Project Structure

```
agentic-soc/
├── api/              # FastAPI backend (routes, models, auth)
├── agents/           # AI agent runtime (triage, investigation, critic)
├── modules/          # Detection engine (4 modules, 21 rules)
├── dashboard/        # Next.js 15 frontend (12 routes)
├── mcp-servers/      # Model Context Protocol server
├── db/               # Database migrations and seeds
├── simulator/        # E2E test simulator
├── monitoring/       # Prometheus config
├── traefik/          # Reverse proxy config
├── docker-compose.yml
├── .env.example
└── LICENSE
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Author

**Advith Niranjan** - Master of Cybersecurity, RMIT University

- GitHub: [github.com/advithh-n](https://github.com/advithh-n)
- LinkedIn: [linkedin.com/in/advith-niranjan](https://linkedin.com/in/advith-niranjan)
