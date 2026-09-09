# Security policy

## Supported code

Security fixes target the current `main` branch. The `legacy/` directory is retained
only for functional comparison and is not a supported deployment target.

## Reporting a vulnerability

Do not open a public issue containing credentials, production logs, packet captures,
private network details or exploit evidence. Contact the repository owner privately
through the security-reporting channel configured on the GitHub repository.

## Secret handling

- Credentials and API tokens are supplied at runtime through protected environment
  files, operating-system credential stores or root-owned configuration files.
- `.env`, runtime databases, snapshots, logs, evidence exports, private keys and
  deployment backups are excluded from Git.
- Example values are placeholders and grant no access.
- The API has no built-in bearer token: `DTLAB_API_TOKENS` must be configured before
  authenticated routes can be used.

If a real secret is ever committed, revoke or rotate it before rewriting Git history.
