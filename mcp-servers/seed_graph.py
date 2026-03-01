"""Seed the Neo4j knowledge graph with Heya's initial asset topology.

Creates nodes for:
- Services (Stripe, Retell AI, n8n, Airtable, etc.)
- Users (admin, team members)
- IPs (known infrastructure IPs)
- Hosts (servers, containers)

And relationships:
- User USES Service
- Service EXPOSES Endpoint
- Host RUNS Service
- IP ASSIGNED_TO Host
"""

import asyncio
import os

from neo4j import AsyncGraphDatabase


async def seed():
    uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    password = os.getenv("NEO4J_PASS", "soc_dev_neo4j_2026!")

    driver = AsyncGraphDatabase.driver(uri, auth=("neo4j", password))

    async with driver.session() as session:
        # Clear existing data (dev only)
        await session.run("MATCH (n) DETACH DELETE n")

        # ── Constraints ──
        await session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (s:Service) REQUIRE s.name IS UNIQUE")
        await session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (u:User) REQUIRE u.email IS UNIQUE")
        await session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (i:IP) REQUIRE i.address IS UNIQUE")
        await session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (h:Host) REQUIRE h.hostname IS UNIQUE")

        # ── Services ──
        services = [
            {"name": "stripe", "type": "payment", "tier": "critical", "environment": "production"},
            {"name": "retell_ai", "type": "voice_agent", "tier": "critical", "environment": "production"},
            {"name": "n8n", "type": "orchestration", "tier": "high", "environment": "production"},
            {"name": "airtable", "type": "database", "tier": "medium", "environment": "production"},
            {"name": "clerk", "type": "authentication", "tier": "critical", "environment": "production"},
            {"name": "soc_api", "type": "security", "tier": "critical", "environment": "production"},
            {"name": "soc_dashboard", "type": "security", "tier": "high", "environment": "production"},
            {"name": "postgresql", "type": "database", "tier": "critical", "environment": "production"},
            {"name": "redis", "type": "cache", "tier": "high", "environment": "production"},
            {"name": "neo4j", "type": "graph_db", "tier": "high", "environment": "production"},
            {"name": "minio", "type": "storage", "tier": "medium", "environment": "production"},
        ]
        for svc in services:
            await session.run(
                "CREATE (s:Service {name: $name, type: $type, tier: $tier, environment: $env})",
                name=svc["name"], type=svc["type"], tier=svc["tier"], env=svc["environment"],
            )

        # ── Users ──
        users = [
            {"email": "admin@heya.au", "role": "owner", "name": "Admin", "department": "engineering"},
            {"email": "founder@heya.au", "role": "owner", "name": "Founder", "department": "executive"},
            {"email": "pm@heya.au", "role": "admin", "name": "Product Manager", "department": "product"},
            {"email": "qa@heya.au", "role": "analyst", "name": "QA Lead", "department": "engineering"},
        ]
        for user in users:
            await session.run(
                "CREATE (u:User {email: $email, role: $role, name: $name, department: $dept})",
                email=user["email"], role=user["role"], name=user["name"], dept=user["department"],
            )

        # ── Hosts (Docker containers) ──
        hosts = [
            {"hostname": "soc-api", "type": "container", "os": "linux", "image": "agentic-soc-api"},
            {"hostname": "soc-modules", "type": "container", "os": "linux", "image": "agentic-soc-module-engine"},
            {"hostname": "soc-agents", "type": "container", "os": "linux", "image": "agentic-soc-agent-runtime"},
            {"hostname": "soc-postgres", "type": "container", "os": "linux", "image": "pgvector/pgvector:pg16"},
            {"hostname": "soc-redis", "type": "container", "os": "linux", "image": "redis/redis-stack"},
            {"hostname": "soc-neo4j", "type": "container", "os": "linux", "image": "neo4j:5-community"},
            {"hostname": "soc-minio", "type": "container", "os": "linux", "image": "minio/minio"},
        ]
        for host in hosts:
            await session.run(
                "CREATE (h:Host {hostname: $hostname, type: $type, os: $os, image: $image})",
                hostname=host["hostname"], type=host["type"], os=host["os"], image=host["image"],
            )

        # ── Known IPs ──
        ips = [
            {"address": "127.0.0.1", "type": "localhost", "owner": "internal"},
            {"address": "185.220.101.42", "type": "tor_exit", "owner": "unknown", "threat_level": "high"},
            {"address": "91.240.118.172", "type": "botnet", "owner": "unknown", "threat_level": "high"},
        ]
        for ip in ips:
            await session.run(
                "CREATE (i:IP {address: $address, type: $type, owner: $owner, threat_level: $threat})",
                address=ip["address"], type=ip["type"], owner=ip["owner"],
                threat=ip.get("threat_level", "unknown"),
            )

        # ── Relationships: User USES Service ──
        user_services = [
            ("admin@heya.au", ["stripe", "retell_ai", "n8n", "clerk", "soc_api", "soc_dashboard"]),
            ("founder@heya.au", ["stripe", "retell_ai", "soc_dashboard"]),
            ("pm@heya.au", ["retell_ai", "airtable", "n8n"]),
            ("qa@heya.au", ["retell_ai", "airtable", "soc_dashboard"]),
        ]
        for email, svcs in user_services:
            for svc in svcs:
                await session.run(
                    "MATCH (u:User {email: $email}), (s:Service {name: $svc}) "
                    "CREATE (u)-[:USES]->(s)",
                    email=email, svc=svc,
                )

        # ── Relationships: Host RUNS Service ──
        host_services = [
            ("soc-api", "soc_api"),
            ("soc-modules", "soc_api"),
            ("soc-postgres", "postgresql"),
            ("soc-redis", "redis"),
            ("soc-neo4j", "neo4j"),
            ("soc-minio", "minio"),
        ]
        for hostname, svc in host_services:
            await session.run(
                "MATCH (h:Host {hostname: $hostname}), (s:Service {name: $svc}) "
                "CREATE (h)-[:RUNS]->(s)",
                hostname=hostname, svc=svc,
            )

        # ── Relationships: Service DEPENDS_ON Service ──
        dependencies = [
            ("soc_api", "postgresql"),
            ("soc_api", "redis"),
            ("soc_api", "neo4j"),
            ("soc_dashboard", "soc_api"),
            ("retell_ai", "n8n"),
            ("n8n", "airtable"),
            ("n8n", "stripe"),
        ]
        for src, tgt in dependencies:
            await session.run(
                "MATCH (a:Service {name: $src}), (b:Service {name: $tgt}) "
                "CREATE (a)-[:DEPENDS_ON]->(b)",
                src=src, tgt=tgt,
            )

        # ── Relationships: Known threat IPs ──
        await session.run(
            "MATCH (i:IP {address: '185.220.101.42'}) "
            "SET i:ThreatActor, i.label = 'Tor Exit Node', i.first_seen = datetime()"
        )
        await session.run(
            "MATCH (i:IP {address: '91.240.118.172'}) "
            "SET i:ThreatActor, i.label = 'Known Botnet IP', i.first_seen = datetime()"
        )

        # ── Threat Actor Nodes ──
        await session.run(
            "CREATE CONSTRAINT IF NOT EXISTS FOR (ta:ThreatActor) REQUIRE ta.name IS UNIQUE"
        )
        await session.run(
            "CREATE CONSTRAINT IF NOT EXISTS FOR (c:Campaign) REQUIRE c.name IS UNIQUE"
        )
        await session.run(
            "CREATE CONSTRAINT IF NOT EXISTS FOR (ioc:IOC) REQUIRE ioc.value IS UNIQUE"
        )

        threat_actors = [
            {
                "name": "FIN7",
                "aliases": "Carbanak, Navigator Group",
                "origin": "Russia",
                "motivation": "Financial",
                "active_since": "2013",
                "ttps": "T1566,T1059,T1071,T1530",
                "description": "Financially motivated threat group targeting hospitality, restaurant, and retail sectors",
            },
            {
                "name": "Lazarus Group",
                "aliases": "HIDDEN COBRA, Zinc",
                "origin": "North Korea",
                "motivation": "Financial, Espionage",
                "active_since": "2009",
                "ttps": "T1566,T1190,T1078,T1486",
                "description": "State-sponsored group known for cryptocurrency theft and destructive attacks",
            },
            {
                "name": "Generic Carding Ring",
                "aliases": "Carding Syndicate",
                "origin": "Unknown",
                "motivation": "Financial",
                "active_since": "2020",
                "ttps": "T1530,T1110",
                "description": "Organized group testing stolen payment card data via automated tools",
            },
        ]
        for ta in threat_actors:
            await session.run(
                "MERGE (ta:ThreatActor {name: $name}) "
                "SET ta.aliases = $aliases, ta.origin = $origin, "
                "ta.motivation = $motivation, ta.active_since = $active_since, "
                "ta.ttps = $ttps, ta.description = $description",
                **ta,
            )

        # Campaigns
        campaigns = [
            {"name": "FIN7-CardHarvest-2025", "actor": "FIN7", "target_sector": "retail",
             "status": "active", "first_seen": "2025-06-01", "description": "Payment card data harvesting campaign"},
            {"name": "Lazarus-CryptoHeist-2025", "actor": "Lazarus Group", "target_sector": "fintech",
             "status": "active", "first_seen": "2025-03-01", "description": "Cryptocurrency exchange targeting campaign"},
            {"name": "CardRing-AutoTest-2026", "actor": "Generic Carding Ring", "target_sector": "e-commerce",
             "status": "active", "first_seen": "2026-01-01", "description": "Automated card testing against payment processors"},
        ]
        for camp in campaigns:
            actor = camp.pop("actor")
            await session.run(
                "MERGE (c:Campaign {name: $name}) "
                "SET c.target_sector = $target_sector, c.status = $status, "
                "c.first_seen = $first_seen, c.description = $description",
                **camp,
            )
            await session.run(
                "MATCH (ta:ThreatActor {name: $actor}), (c:Campaign {name: $camp}) "
                "MERGE (ta)-[:CONDUCTS]->(c)",
                actor=actor, camp=camp["name"],
            )

        # Known IOC nodes linked to threat actors
        known_iocs = [
            {"value": "185.220.101.42", "type": "ip", "actor": "Generic Carding Ring"},
            {"value": "91.240.118.172", "type": "ip", "actor": "Lazarus Group"},
        ]
        for ioc in known_iocs:
            await session.run(
                "MERGE (i:IOC {value: $value}) SET i.type = $type",
                value=ioc["value"], type=ioc["type"],
            )
            await session.run(
                "MATCH (ta:ThreatActor {name: $actor}), (i:IOC {value: $value}) "
                "MERGE (ta)-[:USES_IOC]->(i)",
                actor=ioc["actor"], value=ioc["value"],
            )
            # Link IOC to IP node if it exists
            await session.run(
                "MATCH (ip:IP {address: $value}), (i:IOC {value: $value}) "
                "MERGE (ip)-[:IS_IOC]->(i)",
                value=ioc["value"],
            )

        # Count results
        result = await session.run("MATCH (n) RETURN count(n) as nodes")
        record = await result.single()
        node_count = record["nodes"]

        result = await session.run("MATCH ()-[r]->() RETURN count(r) as rels")
        record = await result.single()
        rel_count = record["rels"]

        print(f"Graph seeded: {node_count} nodes, {rel_count} relationships")

    await driver.close()


if __name__ == "__main__":
    asyncio.run(seed())
