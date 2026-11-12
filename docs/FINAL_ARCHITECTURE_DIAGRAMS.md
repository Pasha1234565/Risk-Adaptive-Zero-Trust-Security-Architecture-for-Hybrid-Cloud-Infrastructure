# Final architecture diagrams

Editable Mermaid diagrams drawn from the code in this repository (module and function names
are the real ones). GitHub renders them directly; they can also be pasted into
<https://mermaid.live> for export.

> **Everything here runs in one local Python process with one SQLite file.** The "private
> cloud" and "public cloud" are labels (`resources.zone`) on records in the local inventory.
> The IdP, PDP and PEP are logical roles played by modules of the same FastAPI application.
> There is no AWS, VPC, VPN, Kubernetes or network enforcement behind these diagrams.

## 1. Overall system architecture

```mermaid
flowchart LR
    subgraph Client["Browser (operator or user)"]
        UI["Pages + vanilla JS<br/>app/templates, app/static/js<br/>CSP: script-src 'self'"]
    end

    subgraph App["FastAPI application - app/main.py (one local process)"]
        direction TB
        MW["Security headers middleware<br/>validation and error handlers"]
        AUTH["Auth API<br/>/api/auth/login, logout, me"]
        PDP["PDP<br/>/api/access/evaluate"]
        MFA["Step-up<br/>/api/access/challenge"]
        PEP["PEP<br/>/api/access/preview"]
        MON["Monitoring<br/>/api/events, /api/alerts, /api/dashboard"]
        SIM["Simulation + evaluation<br/>/api/sim/*, /api/evaluation/*"]
        ADM["Administration<br/>/api/admin/* (is_admin)"]
    end

    subgraph Core["Engine modules"]
        SEC["security.py<br/>PBKDF2, HS256 tokens, TOTP"]
        CRY["mfa_crypto.py<br/>AES-256-GCM secrets"]
        RISK["risk.py<br/>signals, policies, decisions, challenges"]
        ANO["anomaly.py<br/>IsolationForest + rules"]
        SIMU["simulator.py<br/>normal traffic + 12 scenarios"]
        EVAL["evaluation.py<br/>metrics and timings"]
    end

    subgraph Store["Local files - data/ (git-ignored)"]
        DB[("zerotrust.db<br/>SQLite, WAL")]
        KEYS["signing.key<br/>mfa.key"]
        MODEL["behaviour_model.joblib"]
    end

    UI -->|HTTP, HttpOnly session cookie| MW
    MW --> AUTH & PDP & MFA & PEP & MON & SIM & ADM
    AUTH --> SEC
    PDP --> RISK
    MFA --> RISK
    RISK --> ANO
    RISK --> CRY
    RISK --> SEC
    SIM --> SIMU --> RISK
    SIM --> EVAL --> SIMU
    SEC --> KEYS
    CRY --> KEYS
    ANO --> MODEL
    RISK --> DB
    AUTH --> DB
    MON --> DB
    PEP --> DB
    ADM --> DB
```

## 2. Access request lifecycle

```mermaid
sequenceDiagram
    autonumber
    actor U as Signed-in user
    participant API as main.py
    participant R as risk.evaluate()
    participant A as anomaly model
    participant DB as SQLite

    U->>API: POST /api/access/evaluate {device_id, resource_id, context, user_id?}
    API->>API: actor = session user (require_principal)
    alt user_id given and != actor
        API->>API: require security_admin / analyst, else 403
    end
    API->>API: validate AccessContext (bounds, geo preset, enums) else 422
    API->>R: evaluate(subject, device, resource, context, actor, session)
    R->>DB: load user, device, resource, policies
    R->>R: device must belong to subject, else 400
    R->>A: score(9 features)
    A-->>R: anomaly score, rule hits, top factors
    R->>R: 6 weighted signals + policy escalation + hard controls
    R->>R: thresholds -> ALLOW / CHALLENGE / RESTRICT / BLOCK
    R->>DB: INSERT event (subject + actor_user_id)
    opt RESTRICT or BLOCK
        R->>DB: INSERT alert
    end
    opt CHALLENGE
        R->>DB: INSERT mfa_challenges (hashed id, binding, mode, 180 s)
    end
    R-->>U: decision, risk, reasons, signals, challenge id
    U->>API: POST /api/access/preview {event_id}
    API->>DB: load event (own event, or SOC role)
    alt decision ALLOW
        API-->>U: full synthetic records
    else decision RESTRICT
        API-->>U: masked, read-only records
    else CHALLENGE or BLOCK
        API-->>U: 403 PEP denied
    end
```

## 3. Identity and MFA verification

```mermaid
flowchart TD
    L["POST /api/auth/login"] --> T{"5 failures in 5 min<br/>for this e-mail?"}
    T -->|yes| T429["429, try later"]
    T -->|no| P{"PBKDF2-SHA256<br/>120,000 iterations"}
    P -->|wrong| F401["401, attempt recorded"]
    P -->|ok, active| TOK["HS256 token: sub, iat, exp 8 h, random jti<br/>HttpOnly SameSite=Lax cookie"]
    TOK --> REQ["Every API request:<br/>signature, exp, jti not in revoked_sessions"]
    REQ -->|logout| REV["jti stored in revoked_sessions until exp"]

    C["POST /api/access/challenge<br/>{challenge_id, code | simulated_outcome}"] --> TX["BEGIN IMMEDIATE (SQLite write lock)"]
    TX --> S1{"row pending, not expired?"}
    S1 -->|no| E400["400 Challenge expired or already used"]
    S1 -->|yes| S2{"same actor and session hash?"}
    S2 -->|no| E400
    S2 -->|yes| S3{"bound event unchanged?"}
    S3 -->|no| INV["status invalidated, 400"]
    S3 -->|yes| MODE{"mode"}
    MODE -->|simulation| SO{"simulated_outcome"}
    SO -->|success| OKS["consume, outcome step_up_simulated<br/>mfa_attempts mode=simulation"]
    SO -->|failure| CNT["failed_attempts + 1 (3rd cancels, 429)"]
    MODE -->|live| THR{"6 live failures in 15 min<br/>for the subject?"}
    THR -->|yes| E429["429 + Retry-After"]
    THR -->|no| DEC["decrypt seed: AES-256-GCM<br/>(503 if impossible)"]
    DEC --> TOTP{"code matches a step within +-1<br/>AND step newer than totp_counters?"}
    TOTP -->|no| CNT
    TOTP -->|yes| OKL["consume row, advance counter,<br/>re-evaluate with mfa_verified = true"]
```

## 4. Isolation Forest workflow

```mermaid
flowchart LR
    subgraph Train["Training - anomaly.train() (first start or admin retrain)"]
        B["baseline_samples(n=1200, seed=7)<br/>synthetic normal sessions"] --> IF["IsolationForest<br/>180 trees, contamination 0.04"]
        IF --> N["normalise -score_samples<br/>to 0-1 using 1st / 99th percentiles"]
        N --> TH["threshold = 95th percentile<br/>clipped to 0.35-0.85 (0.7862)"]
        TH --> SAVE["behaviour_model.joblib<br/>(written to temp file, then renamed)"]
    end
    subgraph Score["Scoring - BehaviourModel.score()"]
        X["9 features: hour, requests_last_5m,<br/>geo_distance_km, failed_attempts_24h,<br/>device_trust, bytes_out_mb, session_minutes,<br/>sensitivity, new_device"] --> ISO["isolation score 0-1"]
        ISO --> RULES["contextual rule floors<br/>e.g. geo >= 1500 km -> 0.80,<br/>bytes_out >= 250 MB -> 0.82"]
        RULES --> OUT["score = max(isolation, floors)<br/>is_anomaly = score >= threshold"]
        X --> Z["z-scores vs baseline mean/std<br/>top_factors where z > 0.75"]
    end
    SAVE -.loaded by.-> ISO
```

## 5. Risk scoring and decisions

```mermaid
flowchart TD
    IN["subject, device, resource, context"] --> SIG
    subgraph SIG["Six signals, each 0-1 x weight (weights normalised to 100)"]
        S1["behaviour 30<br/>anomaly score"]
        S2["device 20<br/>trust, managed, compliant, new"]
        S3["identity 12<br/>status, MFA, privileged / external role"]
        S4["resource 14<br/>sensitivity low..critical"]
        S5["request 14<br/>hour, failures, rate, distance, country, threat intel"]
        S6["session 10<br/>concurrency, duration, new device"]
    end
    SIG --> BASE["base risk = sum of points"]
    BASE --> POL["policy escalation<br/>role not allowed: +18, floor RESTRICT<br/>MFA required and not verified: +20, floor CHALLENGE<br/>device trust below policy: +15, floor CHALLENGE"]
    POL --> RS["risk = min(100, base + escalation)"]
    RS --> BAND{"risk band"}
    BAND -->|"< 40"| AL["ALLOW"]
    BAND -->|"40-59.9"| CH["CHALLENGE"]
    BAND -->|"60-79.9"| RE["RESTRICT"]
    BAND -->|">= 80"| BL["BLOCK"]
    AL & CH & RE & BL --> MAX["decision = max(band, policy floor)"]
    MAX --> HARD{"hard controls:<br/>identity not active,<br/>device trust < 20,<br/>malicious source IP"}
    HARD -->|any true| BLK["BLOCK"]
    HARD -->|none| FINAL["final decision + ranked reasons"]
```

## 6. Database entity relationships

```mermaid
erDiagram
    users ||--o{ devices : owns
    users ||--o{ events : "subject (user_id)"
    users ||--o{ events : "actor (actor_user_id)"
    devices ||--o{ events : used
    resources ||--o{ events : requested
    events ||--o{ alerts : raises
    events ||--o{ mfa_challenges : "step-up for"
    users ||--o{ mfa_challenges : "subject / actor"
    users ||--o{ mfa_attempts : "verified for"
    users ||--o| totp_counters : "last accepted step"
    users ||--o{ revoked_sessions : "logged out"

    users {
        INTEGER id PK
        TEXT email
        TEXT role
        TEXT password_hash "pbkdf2_sha256"
        TEXT mfa_secret "enc:v1 AES-GCM"
        INTEGER is_admin
        TEXT status
    }
    devices {
        INTEGER id PK
        INTEGER user_id FK
        INTEGER managed
        INTEGER compliant
        REAL trust_score
    }
    resources {
        INTEGER id PK
        TEXT name
        TEXT zone "private or public (simulated)"
        TEXT category
        TEXT sensitivity
    }
    policies {
        INTEGER id PK
        TEXT resource_category
        REAL required_device_trust
        INTEGER mfa_required
        TEXT allowed_roles
        INTEGER enabled
    }
    events {
        INTEGER id PK
        INTEGER user_id FK
        INTEGER device_id FK
        INTEGER resource_id FK
        INTEGER actor_user_id FK
        TEXT decision
        REAL risk_score
        REAL anomaly_score
        TEXT scenario
        INTEGER ground_truth
        TEXT outcome
    }
    alerts {
        INTEGER id PK
        INTEGER event_id FK
        TEXT severity
        TEXT status
    }
    mfa_challenges {
        TEXT token_hash PK "SHA-256"
        INTEGER event_id FK
        INTEGER user_id FK
        INTEGER actor_user_id FK
        TEXT session_hash "SHA-256"
        TEXT mode "live or simulation"
        REAL expires_at
        INTEGER failed_attempts
        TEXT status
    }
    mfa_attempts {
        INTEGER id PK
        INTEGER user_id FK
        INTEGER actor_user_id FK
        INTEGER success
        TEXT mode
    }
    totp_counters {
        INTEGER user_id PK
        INTEGER last_counter
    }
    revoked_sessions {
        TEXT jti PK
        INTEGER expires_at
    }
    login_attempts {
        INTEGER id PK
        TEXT email
        INTEGER success
    }
    eval_runs {
        INTEGER id PK
        TEXT metrics "JSON"
    }
    settings {
        TEXT key PK
        TEXT value "JSON"
    }
```

`policies` match resources by `resource_category` (not a foreign key); `login_attempts`,
`eval_runs` and `settings` stand alone.

## 7. Simulated hybrid-cloud trust zones

```mermaid
flowchart LR
    subgraph Subjects["Identities and devices (seeded records)"]
        U1["security_admin · analyst · developer<br/>finance · contractor · service"]
        D1["10 devices with trust 38-96,<br/>managed / unmanaged, compliant / not"]
    end

    subgraph Boundary["Zero-trust boundary - logical roles in one FastAPI process"]
        IDP["IdP role<br/>login, sessions, TOTP"]
        PDPZ["PDP role<br/>risk.evaluate()"]
        PEPZ["PEP role<br/>/api/access/preview<br/>returns synthetic records"]
    end

    subgraph Private["SIMULATED private data centre (zone = private)"]
        P1["identity-provider · high"]
        P2["finance-db · critical"]
        P3["hr-portal · high"]
        P4["internal-wiki · low"]
        P5["dev-vm-01 · medium"]
        P6["k8s-prod · critical"]
        P7["vpn-gateway · high"]
    end

    subgraph Public["SIMULATED public cloud (zone = public)"]
        Q1["public-web · low"]
        Q2["api-gateway · high"]
        Q3["analytics-lake · medium"]
        Q4["ml-training · medium"]
        Q5["backup-vault · critical"]
    end

    U1 --> IDP --> PDPZ --> PEPZ
    D1 --> PDPZ
    PEPZ -.->|"inventory record only,<br/>no network path"| Private
    PEPZ -.->|"inventory record only,<br/>no network path"| Public
```

The zone affects risk only through the resource's category and sensitivity and through the
policies that match it; no request ever leaves the local process.
