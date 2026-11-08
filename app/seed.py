"""Demo identity, device, resource and policy inventory.

These records model a small enterprise operating a hybrid estate: a private
data centre (identity provider, finance database, Kubernetes, internal wiki,
developer VMs) and a public cloud tenancy (API gateway, web tier, analytics
lake, ML training, backup vault).
"""

from __future__ import annotations

from . import config, database, security

DEMO_USERS = [
    {
        "email": "admin@hybridcloud.io",
        "name": "Farhaan Pasha",
        "role": "security_admin",
        "department": "Security",
        "password": "Admin#2026",
        "is_admin": 1,
        "mfa_enabled": 1,
        "status": "active",
    },
    {
        "email": "analyst@hybridcloud.io",
        "name": "Aisha Rahman",
        "role": "analyst",
        "department": "Security Operations",
        "password": "Analyst#2026",
        "is_admin": 0,
        "mfa_enabled": 1,
        "status": "active",
    },
    {
        "email": "dev@hybridcloud.io",
        "name": "Rohan Mehta",
        "role": "developer",
        "department": "Engineering",
        "password": "Dev#2026",
        "is_admin": 0,
        "mfa_enabled": 1,
        "status": "active",
    },
    {
        "email": "finance@hybridcloud.io",
        "name": "Priya Nair",
        "role": "finance",
        "department": "Finance",
        "password": "Finance#2026",
        "is_admin": 0,
        "mfa_enabled": 1,
        "status": "active",
    },
    {
        "email": "contractor@hybridcloud.io",
        "name": "Imran Khan",
        "role": "contractor",
        "department": "External",
        "password": "Guest#2026",
        "is_admin": 0,
        "mfa_enabled": 1,
        "status": "active",
    },
    {
        "email": "svc-backup@hybridcloud.io",
        "name": "svc-backup",
        "role": "service",
        "department": "Platform",
        "password": "Service#2026",
        "is_admin": 0,
        "mfa_enabled": 0,
        "status": "active",
    },
]

DEMO_DEVICES = [
    ("admin@hybridcloud.io", "FARHAAN-LT-01", "laptop", "Windows 11", 1, 1, 96, "fp-farhaan-01"),
    ("admin@hybridcloud.io", "iPhone 15 (personal)", "mobile", "iOS 18", 0, 1, 62, "fp-farhaan-phone"),
    ("analyst@hybridcloud.io", "AISHA-LT-02", "laptop", "Ubuntu 24.04", 1, 1, 94, "fp-aisha-02"),
    ("analyst@hybridcloud.io", "SOC analysis VM", "vm", "Debian 12", 1, 1, 88, "fp-aisha-vm"),
    ("dev@hybridcloud.io", "ROHAN-LT-07", "laptop", "macOS 15", 1, 0, 68, "fp-rohan-07"),
    ("dev@hybridcloud.io", "dev-vm-01", "vm", "Ubuntu 24.04", 1, 1, 90, "fp-rohan-vm"),
    ("finance@hybridcloud.io", "PRIYA-LT-03", "laptop", "Windows 11", 1, 1, 92, "fp-priya-03"),
    ("contractor@hybridcloud.io", "CONTRACTOR-LT-11", "laptop", "Windows 10", 0, 0, 38, "fp-imran-11"),
    ("contractor@hybridcloud.io", "CONTRACTOR-LT-12", "laptop", "Windows 11", 1, 1, 72, "fp-imran-12"),
    ("svc-backup@hybridcloud.io", "backup-runner-01", "server", "Amazon Linux 2023", 1, 1, 75, "fp-svc-backup"),
]

DEMO_RESOURCES = [
    ("identity-provider", "private", "Keycloak 26", "identity", "high", "Security", "Primary SSO and identity provider for both clouds."),
    ("finance-db", "private", "PostgreSQL 16", "database", "critical", "Finance", "General ledger, payroll and invoice records."),
    ("hr-portal", "private", "Django 5", "web", "high", "People", "Employee records, contracts and appraisals."),
    ("internal-wiki", "private", "Confluence", "collaboration", "low", "Platform", "Engineering documentation and runbooks."),
    ("dev-vm-01", "private", "Ubuntu 24.04", "compute", "medium", "Engineering", "Shared build and integration VM."),
    ("k8s-prod", "private", "Kubernetes 1.31", "orchestration", "critical", "Platform", "Production workload cluster in the private data centre."),
    ("public-web", "public", "Nginx + CDN", "web", "low", "Marketing", "Public marketing site fronted by a CDN."),
    ("api-gateway", "public", "Kong 3.8", "api", "high", "Platform", "North-south API entry point for partner traffic."),
    ("analytics-lake", "public", "Amazon S3", "storage", "medium", "Data", "Curated analytics datasets and event exports."),
    ("ml-training", "public", "SageMaker", "compute", "medium", "Data", "Model training jobs and notebooks."),
    ("backup-vault", "public", "S3 Glacier", "storage", "critical", "Platform", "Immutable cross-region backups."),
    ("vpn-gateway", "private", "WireGuard", "network", "high", "Network", "Site-to-site tunnel linking private and public zones."),
]

DEMO_POLICIES = [
    {
        "name": "Baseline verified-device access",
        "description": "Every request must originate from a device with a trust score of at least 45; MFA is required for interactive users.",
        "resource_category": "*",
        "required_device_trust": 45,
        "mfa_required": 1,
        "allowed_roles": "",
        "effect": "enforce",
    },
    {
        "name": "Critical finance data",
        "description": "Only security administrators, analysts and finance staff may reach ledger data, from managed devices with step-up MFA.",
        "resource_category": "database",
        "required_device_trust": 80,
        "mfa_required": 1,
        "allowed_roles": "security_admin,analyst,finance",
        "effect": "enforce",
    },
    {
        "name": "Production orchestration",
        "description": "Kubernetes control plane access is limited to platform engineering and security; high-trust managed devices only.",
        "resource_category": "orchestration",
        "required_device_trust": 85,
        "mfa_required": 1,
        "allowed_roles": "security_admin,developer",
        "effect": "enforce",
    },
    {
        "name": "Storage egress guard",
        "description": "Analytics and backup storage require MFA and a trusted device; mass egress is monitored.",
        "resource_category": "storage",
        "required_device_trust": 70,
        "mfa_required": 1,
        "allowed_roles": "security_admin,analyst,developer,finance",
        "effect": "enforce",
    },
    {
        "name": "Identity provider protection",
        "description": "Only security administrators may administer the SSO provider.",
        "resource_category": "identity",
        "required_device_trust": 85,
        "mfa_required": 1,
        "allowed_roles": "security_admin",
        "effect": "enforce",
    },
    {
        "name": "Public web read-only",
        "description": "The public marketing site is readable from any compliant device without step-up MFA.",
        "resource_category": "web",
        "required_device_trust": 30,
        "mfa_required": 0,
        "allowed_roles": "",
        "effect": "enforce",
    },
    {
        "name": "Collaboration baseline",
        "description": "Internal documentation is available to staff and contractors on compliant devices.",
        "resource_category": "collaboration",
        "required_device_trust": 40,
        "mfa_required": 0,
        "allowed_roles": "",
        "effect": "enforce",
    },
    {
        "name": "Network edge administration",
        "description": "VPN and network configuration is restricted to security and platform engineering.",
        "resource_category": "network",
        "required_device_trust": 80,
        "mfa_required": 1,
        "allowed_roles": "security_admin,developer",
        "effect": "enforce",
    },
    {
        "name": "Developer compute sandbox",
        "description": "Shared compute is available to engineering, analytics and security on managed devices.",
        "resource_category": "compute",
        "required_device_trust": 55,
        "mfa_required": 1,
        "allowed_roles": "security_admin,developer,analyst",
        "effect": "enforce",
    },
    {
        "name": "Partner API access",
        "description": "API gateway access requires a trusted device and MFA; least-privilege roles only.",
        "resource_category": "api",
        "required_device_trust": 70,
        "mfa_required": 1,
        "allowed_roles": "security_admin,developer,analyst,finance",
        "effect": "enforce",
    },
    {
        "name": "Contractor observation",
        "description": "Flags contractor sessions to low-sensitivity resources for enhanced monitoring.",
        "resource_category": "collaboration",
        "required_device_trust": 40,
        "mfa_required": 0,
        "allowed_roles": "",
        "effect": "monitor",
    },
]


def seed_identity() -> None:
    """Create the demo inventory and default engine configuration."""
    database.init_db()
    if not database.is_empty():
        return

    now = database.utcnow()
    with database.get_db() as conn:
        for user in DEMO_USERS:
            conn.execute(
                """INSERT INTO users
                   (email, name, role, department, password_hash, mfa_enabled,
                    mfa_secret, status, is_admin, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    user["email"],
                    user["name"],
                    user["role"],
                    user["department"],
                    security.hash_password(user["password"]),
                    user["mfa_enabled"],
                    security.generate_totp_secret(),
                    user["status"],
                    user["is_admin"],
                    now,
                ),
            )

        user_ids = {
            row["email"]: row["id"]
            for row in conn.execute("SELECT id, email FROM users").fetchall()
        }
        for email, name, kind, os_name, managed, compliant, trust, fingerprint in DEMO_DEVICES:
            conn.execute(
                """INSERT INTO devices
                   (user_id, name, kind, os, managed, compliant, trust_score,
                    fingerprint, last_seen)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (user_ids[email], name, kind, os_name, managed, compliant,
                 trust, fingerprint, now),
            )

        for name, zone, service, category, sensitivity, owner, description in DEMO_RESOURCES:
            conn.execute(
                """INSERT INTO resources
                   (name, zone, service, category, sensitivity, owner, description)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (name, zone, service, category, sensitivity, owner, description),
            )

        for policy in DEMO_POLICIES:
            conn.execute(
                """INSERT INTO policies
                   (name, description, resource_category, required_device_trust,
                    mfa_required, allowed_roles, effect, enabled)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 1)""",
                (
                    policy["name"],
                    policy["description"],
                    policy["resource_category"],
                    policy["required_device_trust"],
                    policy["mfa_required"],
                    policy["allowed_roles"],
                    policy["effect"],
                ),
            )

    database.set_setting("thresholds", config.DEFAULT_THRESHOLDS)
    database.set_setting("weights", config.DEFAULT_WEIGHTS)
    database.set_setting("policy_version", 1)
    database.set_setting("demo_seeded_at", now)
