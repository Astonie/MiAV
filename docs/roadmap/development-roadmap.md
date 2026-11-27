# Development roadmap

All milestones are planned, except the current foundation. Tests and security
review are part of each milestone; thresholds below are acceptance gates, not
claims about current performance.

| Milestone | Measurable deliverables and acceptance |
| --- | --- |
| Foundation | Install on Python 3.11+, run the version CLI, and pass the initial automated tests, lint, formatting and type checks. No protection is claimed. |
| M1: Core scanning | Scan individual files and recursive directories; stream SHA-256, extract metadata, provide explainable basic heuristics and classifications, and emit JSON reports. Tests cover unreadable files, cancellation, symlinks, clean files and EICAR; resource limits are documented and measured. A secure quarantine design and implementation are required for the full 0.1.0 scope; M7 tracks its dedicated completion gate. |
| M2: Signatures and YARA | Match versioned SHA-256 signatures and YARA rules; reject unverified updates. Tests cover matches, non-matches, malformed databases and update verification. |
| M3: Heuristics | Produce explainable findings for documented entropy and executable characteristics; test known benign and suspicious fixtures and publish measured false positives. |
| M4: ML classification | Publish dataset provenance, reproducible preprocessing and model version; report precision, recall, F1, false-positive rate and confusion matrix on a held-out dataset. Document limitations; no automatic deletion based on ML alone. |
| M5: Real-time monitoring | Deliver a Windows user-space monitoring adapter with capability and health reporting; test event delivery, failure and shutdown. Document event-loss and resource measurements. |
| M6: Ransomware detection | Implement explainable rules for documented mass-modification indicators; evaluate on controlled benign and simulated activity, reporting detection and false-positive results without executing live malware. |
| M7: Quarantine and remediation | Record hashes, original paths, findings and audit events; protect storage and support authorized recovery. Test restoration, interrupted operations, tampering, symlinks and reparse points; high-impact actions require policy authorization. |
| M8: Management server | Authenticate endpoints and administrators; expose documented, authorized APIs for endpoint registration, event ingestion and task management. Integration tests cover authorization, TLS configuration and invalid inputs. |
| M9: Dashboard | Provide authenticated endpoint inventory, threat and incident views with loading and error states; test access restrictions and core workflows. |
| M10: Windows production readiness | Exercise installation, updates, recovery and protection capabilities on Windows 10 and 11; publish performance, security-review and supported-platform results with no unresolved critical defects. |
| M11: Linux agent | Implement and test supported Linux platform adapters, installation and capability reporting on documented distributions; publish limitations and resource measurements. |
| M12: macOS agent | Implement and test supported macOS platform adapters, installation and capability reporting on documented versions; publish limitations and resource measurements. |

M1 remains the immediate development priority. Milestone numbers describe
capability areas, not permission to ship an incomplete 0.1.0 scope; quarantine
must meet its security gate before a release claims that capability.
