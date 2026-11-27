# MiAV — Agent Engineering Instructions

**Project:** MiAV (Mitra Intelligent Antivirus)  
**Organisation:** Mitra Systems Limited  
**Product Category:** AI-Powered Antivirus and Endpoint Detection & Response (EDR)  
**Initial Version:** 0.1.0  
**Document Version:** 1.0  
**Status:** Initial Development  
**Primary Target:** Windows 10/11  
**Future Targets:** Linux and macOS  

---

# 1. Project Overview

MiAV (Mitra Intelligent Antivirus) is a cross-platform, AI-powered antivirus and Endpoint Detection and Response (EDR) platform developed to detect, analyse, prevent and respond to modern cybersecurity threats.

The platform combines traditional antivirus technologies with heuristic analysis, behavioural monitoring and machine learning to provide intelligent endpoint protection.

MiAV is designed for individual users and enterprise environments.

The long-term objective is to provide a centrally managed endpoint security platform capable of protecting hundreds or thousands of endpoints.

## 1.1 Core Objectives

MiAV must:

1. Detect known malware using signatures and threat intelligence.
2. Identify suspicious files using heuristic analysis.
3. Classify potentially malicious files using machine learning.
4. Monitor endpoint processes and filesystem activities.
5. Detect suspicious behaviours, including ransomware-like activities.
6. Quarantine detected malicious files safely.
7. Provide centralised endpoint management.
8. Support security incident investigation and response.
9. Maintain low endpoint resource consumption.
10. Support Windows, Linux and macOS.

## 1.2 Development Philosophy

MiAV must be developed as a security product, not merely a demonstration antivirus application.

All implementation decisions must prioritise:

- Security.
- Reliability.
- Performance.
- Maintainability.
- Extensibility.
- Detection accuracy.
- Cross-platform compatibility.
- Operational transparency.

Never introduce functionality simply to demonstrate technical complexity.

Every feature must solve an identifiable security problem.

---

# 2. System Architecture

MiAV follows a distributed endpoint protection architecture.

The platform consists of four primary components.

## 2.1 Endpoint Agent

The endpoint agent runs on individual computers.

Responsibilities:

- File and directory scanning.
- Malware signature verification.
- Heuristic analysis.
- Machine learning-assisted detection.
- Filesystem monitoring.
- Process monitoring.
- Threat quarantine.
- Endpoint health reporting.
- Secure communication with the management server.

The endpoint agent must be lightweight and independently deployable.

## 2.2 Detection Engine

The detection engine is responsible for analysing files and activities.

It consists of:

- Signature detection.
- YARA rule evaluation.
- Static file analysis.
- Heuristic analysis.
- Behavioural detection.
- Machine learning classification.
- Threat scoring.

Detection components must be modular and independently testable.

## 2.3 Management Server

The management server provides centralised endpoint administration.

Responsibilities:

- Endpoint registration.
- Authentication and authorisation.
- Security event ingestion.
- Threat intelligence distribution.
- Scan task management.
- Incident management.
- Endpoint health monitoring.
- Administrative operations.

The server must expose secure REST APIs.

## 2.4 Management Dashboard

The dashboard provides administrators with visibility into the security posture of managed endpoints.

It should support:

- Endpoint inventory.
- Threat monitoring.
- Security incident management.
- Scan management.
- Quarantine administration.
- Threat intelligence management.
- Endpoint health monitoring.
- Security reporting.

---

# 3. Technology Stack

Use the following technologies unless an architectural decision explicitly approves an alternative.

| Component | Technology |
|---|---|
| Initial endpoint agent | Python |
| Performance-critical components | Rust |
| Backend API | FastAPI |
| Frontend | React + TypeScript |
| Database | PostgreSQL |
| Task processing | Celery |
| Message broker | Redis |
| Signature detection | SHA-256 |
| Pattern detection | YARA |
| PE analysis | LIEF |
| Machine learning | Scikit-learn / XGBoost |
| Communication | HTTPS / WebSockets |
| Containerisation | Podman |
| Testing | Pytest |
| API documentation | OpenAPI |

Use supported and maintained versions of dependencies.

Do not introduce unnecessary dependencies.

---

# 4. Cross-Platform Engineering

MiAV must support Windows, Linux and macOS.

Although Windows is the first implementation target, the architecture must not assume Windows-specific functionality throughout the codebase.

## 4.1 Platform Separation

All operating-system-specific functionality must be isolated inside platform-specific modules.

Expected structure:

```text
agent/
├── core/
├── platform/
│   ├── windows/
│   ├── linux/
│   └── macos/
```

Platform-independent detection logic must remain inside shared modules.

## 4.2 Platform Abstraction

Use interfaces and abstract classes for operating-system-specific operations.

Examples:

- Filesystem monitoring.
- Process monitoring.
- System information collection.
- File isolation.
- Real-time protection.
- Endpoint telemetry.

Do not implement platform-specific functionality directly inside shared detection components.

## 4.3 Platform Compatibility

Where functionality is unavailable on a particular operating system:

- Report the capability as unsupported.
- Provide a clear implementation status.
- Do not silently simulate protection.
- Never report an endpoint as fully protected when critical security capabilities are unavailable.

---

# 5. Repository Structure

Maintain a modular repository.

Initial proposed structure:

```text
MiAV/
│
├── agent/
│   ├── core/
│   ├── platform/
│   │   ├── windows/
│   │   ├── linux/
│   │   └── macos/
│   ├── scanners/
│   ├── detection/
│   ├── monitoring/
│   ├── quarantine/
│   └── communication/
│
├── engine/
│   ├── signatures/
│   ├── yara/
│   ├── heuristics/
│   ├── behavioral/
│   └── machine_learning/
│
├── server/
│   ├── api/
│   ├── services/
│   ├── database/
│   ├── security/
│   └── workers/
│
├── dashboard/
│
├── ml/
│   ├── datasets/
│   ├── preprocessing/
│   ├── training/
│   └── evaluation/
│
├── deployment/
│
├── tests/
│
├── docs/
│   ├── architecture/
│   ├── development/
│   ├── security/
│   └── migration/
│
├── scripts/
│
├── AGENTS.md
├── README.md
└── pyproject.toml
```

Agents may introduce additional directories when justified.

Avoid unnecessary architectural complexity during early development.

---

# 6. Antivirus Detection Requirements

## 6.1 Signature-Based Detection

The detection engine must support:

- SHA-256 file fingerprinting.
- Known malware hash comparison.
- YARA pattern matching.
- Versioned signature databases.
- Signature update verification.

Never rely exclusively on file extensions to identify malware.

## 6.2 Heuristic Analysis

Analyse suspicious characteristics, including:

- Unusual executable sections.
- High file entropy.
- Suspicious imported APIs.
- Unexpected executable permissions.
- Suspicious embedded strings.
- Abnormal executable structures.

Heuristic detection must produce explainable results.

## 6.3 Machine Learning Detection

Machine learning must complement traditional antivirus detection.

Initial algorithms:

- Random Forest.
- XGBoost.
- Gradient Boosting.

Potential features include:

- File size.
- PE characteristics.
- Entropy.
- Section metadata.
- Imported APIs.
- Executable characteristics.

Every model must have:

- A documented training dataset.
- Reproducible preprocessing.
- Evaluation results.
- Version information.
- Performance metrics.
- Known limitations.

Required evaluation metrics:

- Precision.
- Recall.
- F1-score.
- False-positive rate.
- Confusion matrix.

Do not present model confidence as proof that a file is malicious.

## 6.4 Behavioural Detection

Monitor suspicious endpoint activities.

Examples:

- Unusual process execution.
- Suspicious process relationships.
- Unexpected persistence mechanisms.
- Unusual filesystem modifications.
- Mass file encryption indicators.
- Suspicious script execution.

Detection must use explainable behavioural rules.

---

# 7. Quarantine and Remediation

Quarantine operations must be designed with security and recoverability in mind.

Requirements:

1. Store quarantined files outside ordinary user-accessible directories.
2. Restrict access using appropriate operating-system permissions.
3. Record original file locations.
4. Calculate file hashes before quarantine.
5. Record detection information.
6. Prevent accidental execution.
7. Support authorised restoration.
8. Maintain an audit trail.

Quarantine operations must avoid following symbolic links or reparse points into unintended locations.

Never permanently delete files merely because an ML model classifies them as suspicious.

High-impact remediation must require explicit policy authorisation.

---

# 8. Real-Time Endpoint Monitoring

Real-time monitoring must be implemented using appropriate native operating-system facilities.

Windows:
- Windows Event Tracing (ETW).
- Windows process APIs.
- Windows filesystem monitoring.
- Antimalware Scan Interface (AMSI).
- Filesystem minifilters where justified.

Linux:
- inotify.
- fanotify.
- eBPF where appropriate.

macOS:
- Endpoint Security framework.
- FSEvents.

Kernel-level integrations must be introduced only when user-space capabilities are insufficient.

Any driver or privileged system component must receive dedicated security review and testing.

---

# 9. Security Engineering Standards

Security is a primary engineering requirement.

## 9.1 Authentication

- Secure endpoint registration.
- Strong endpoint identity.
- Token-based authentication.
- Role-based access control.
- Secure administrative sessions.

## 9.2 Communication

- HTTPS/TLS for all server communication.
- Authenticated endpoint connections.
- Certificate verification.
- Secure token storage.
- Protection against replay attacks.

Never disable TLS certificate validation in production.

## 9.3 Secrets Management

- Never hardcode credentials.
- Never commit API keys.
- Never expose database passwords.
- Use environment variables or secure secret stores.
- Maintain separate development and production configurations.

## 9.4 Input Validation

Validate all external input.

Treat files, filenames, process metadata, API requests and endpoint telemetry as untrusted.

Prevent:

- Path traversal.
- Command injection.
- SQL injection.
- Insecure deserialization.
- Arbitrary file execution.
- Privilege escalation.

---

# 10. Development Standards

## 10.1 Python

Follow:

- PEP 8.
- Type hints.
- Clear function documentation.
- Modular implementation.
- Dependency management through pyproject.toml.

Use:

- Ruff for linting.
- Pytest for testing.
- Mypy or an equivalent tool for type checking.

Avoid unnecessary global state.

## 10.2 API Development

FastAPI endpoints must:

- Use request and response schemas.
- Validate incoming data.
- Apply authentication and authorisation.
- Return consistent error responses.
- Include API documentation.
- Implement pagination where appropriate.

## 10.3 Frontend

React components must:

- Use TypeScript.
- Follow reusable component patterns.
- Implement appropriate loading and error states.
- Avoid exposing sensitive endpoint information.
- Apply role-based access restrictions.

## 10.4 Database

Database changes must use migrations.

Use appropriate indexes and constraints.

Never store plaintext passwords or sensitive authentication tokens.

---

# 11. Testing Requirements

Every new feature must include appropriate tests.

Testing categories:

1. Unit tests.
2. Integration tests.
3. API tests.
4. Cross-platform compatibility tests.
5. Performance tests.
6. Security tests.
7. Regression tests.

Use controlled malware test samples such as EICAR.

Never execute live malware on production systems or ordinary development machines.

Test quarantine restoration and recovery procedures.

Test false-positive scenarios using legitimate executable files.

---

# 12. AI Coding Agent Instructions

AI coding agents working on MiAV must follow these instructions.

## 12.1 Before Implementation

Before modifying code:

1. Inspect the existing repository.
2. Read the README and relevant documentation.
3. Understand existing architectural decisions.
4. Identify affected modules.
5. Review existing tests.
6. Identify security implications.

Do not assume that a feature has not already been implemented.

## 12.2 During Implementation

AI agents must:

- Preserve existing functionality.
- Follow established architectural patterns.
- Avoid unnecessary rewrites.
- Implement modular components.
- Add appropriate tests.
- Handle errors explicitly.
- Document important design decisions.
- Avoid introducing unapproved dependencies.

Do not create placeholder implementations that falsely imply production functionality.

## 12.3 After Implementation

Before declaring work complete:

1. Run relevant tests.
2. Run linting.
3. Validate type correctness where applicable.
4. Review security implications.
5. Update documentation.
6. Summarise modified files.
7. Report incomplete functionality.
8. Document known limitations.

Never claim that a feature works without verification.

## 12.4 Architectural Decisions

AI agents must not independently:

- Replace the established technology stack.
- Introduce major architectural changes.
- Remove existing security controls.
- Introduce unnecessary microservices.
- Change public API contracts without documentation.
- Implement privileged kernel functionality without explicit approval.

Document significant architectural decisions in:

`docs/architecture/decisions/`

---

# 13. Performance Requirements

MiAV must remain lightweight.

Prioritise:

- Incremental scanning.
- Efficient file hashing.
- Streaming large files.
- Asynchronous task execution.
- Bounded concurrency.
- Resource-aware scheduling.
- Efficient telemetry transmission.

Avoid loading entire files into memory when streaming is possible.

Scanning must support cancellation and graceful shutdown.

Do not allow scanning workloads to overwhelm the endpoint.

---

# 14. Logging and Monitoring

The platform must provide structured logging.

Record:

- Scan initiation and completion.
- Threat detections.
- Quarantine operations.
- Agent registration.
- Authentication failures.
- Signature updates.
- Model updates.
- Administrative actions.

Logs must not contain passwords, authentication tokens or unnecessary sensitive data.

Security events should include timestamps, endpoint identifiers and detection reasons.

---

# 15. Versioning and Release Management

Follow Semantic Versioning.

Format:

`MAJOR.MINOR.PATCH`

Examples:

- 0.1.0 — Initial detection engine.
- 0.2.0 — Signature and heuristic detection.
- 0.3.0 — ML classification.
- 1.0.0 — Initial production release.

Maintain a CHANGELOG.md.

All releases must include:

- Release notes.
- Implemented features.
- Known limitations.
- Security considerations.
- Testing results.

---

# 16. Development Roadmap

Development must follow these milestones.

| Milestone | Description | Priority |
|---|---|---|
| M1 | Core antivirus scanning engine | Critical |
| M2 | Signature and YARA detection | Critical |
| M3 | Heuristic analysis | High |
| M4 | ML malware classification | High |
| M5 | Real-time endpoint monitoring | High |
| M6 | Ransomware detection | High |
| M7 | Quarantine and remediation | Critical |
| M8 | Central management server | High |
| M9 | React security dashboard | Medium |
| M10 | Windows production-ready agent | Critical |
| M11 | Linux agent | Medium |
| M12 | macOS agent | Medium |

Each milestone must have measurable acceptance criteria.

---

# 17. Initial Development Scope: MiAV 0.1.0

The first development release must focus exclusively on the core antivirus engine.

Required capabilities:

1. Command-line interface.
2. Recursive directory scanning.
3. Individual file scanning.
4. SHA-256 fingerprinting.
5. File metadata extraction.
6. Basic heuristic analysis.
7. Threat classification.
8. JSON scan reports.
9. Secure quarantine management.
10. Automated testing.

YARA integration should be included if it can be implemented without compromising the stability of the initial release.

Do not prematurely introduce the management server, dashboard or distributed agent infrastructure into M1.

The architecture must accommodate these future components.

## Initial CLI Design

Example commands:

```bash
miav scan /path/to/directory

miav scan /path/to/file.exe

miav scan /path/to/directory --recursive

miav quarantine list

miav report --latest

miav version
```

The CLI must provide clear detection explanations.

---

# 18. Definition of Done

A feature is considered complete only when:

- Its requirements are satisfied.
- Implementation follows the architecture.
- Security implications have been considered.
- Appropriate tests exist.
- Tests pass.
- Documentation is updated.
- Errors are handled.
- Limitations are documented.
- No critical unresolved defects remain.

A successful build alone does not constitute a completed feature.

---

# 19. Final Engineering Directive

MiAV is intended to become a reliable, intelligent and extensible endpoint security platform.

All contributors and AI coding agents must operate with the understanding that they are developing security-critical software.

Prioritise correctness over speed.

Prioritise security over convenience.

Prioritise explainable detection over unsupported AI predictions.

Never sacrifice endpoint stability for aggressive detection.

**Build MiAV to be trustworthy, maintainable and enterprise-ready.**