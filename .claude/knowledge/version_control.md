# Version Control Tasks

## Workflow

### Before committing

1. Re-read your changes for unnecessary complexity and unclear naming
2. Run the `run-ci` and `sync-docs` skills.

### Commits

- Imperative mood, ≤72 char subject line, one logical change per commit
- Use `feat:` prefix for public interface changes (new endpoints, trait changes, wire type changes)
- Never commit secrets, API keys, or credentials
- Never push directly to main — use feature branches and PRs

### Pull requests

- Describe what the code does now — not discarded approaches or alternatives
- Use plain, factual language. Avoid: critical, crucial, essential, significant, comprehensive, robust, elegant
- Keep the description concise.