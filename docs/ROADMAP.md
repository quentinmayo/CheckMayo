# Roadmap

The preview establishes a tested control plane and a conservative scanner execution contract. The long-term direction is affordable, self-hosted ASPM with interchangeable scanner locations and policies.

1. Harden account lifecycle: email verification, reset, MFA, invitations, group/SCIM synchronization and migration tooling.
2. Harden packages: digest-only production mode, image signature verification, provenance/SBOM, reviewed ZIP rule bundles, multi-service profiles and scanner database distribution.
3. Expand execution: explicit DAST target grants, bounded network broker, cloud-native discovery, elastic EC2/ECS/EKS workers and local parallel worker pools.
4. Deepen report coverage: validated DefectDojo parser matrix, richer findings metadata, portfolio views, duplicate strategies, reimport and remediation tracking.
5. Automate risk workflows: versioned policy bundles, dry-run diffs, PR checks with confidential summaries, ticketing and documented exception expiry.
6. Operate at scale: metrics, durable queue backend, quotas, report retention, encrypted object storage, HA scheduler, release signing and database migrations.
7. Community operations: maintainer/review queues, revocation, publisher reputation, scanner search tags and activated donation account.

Deployment guides are not proof that every cloud path is supported or tested. The validation matrix records the current evidence.
