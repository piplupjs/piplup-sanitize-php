# AGENTS — Project agent guidelines

Purpose: document the conventions, patterns, and safe workflows agents and
contributors should follow when editing this repository so changes stay
consistent with the project's existing design.

## Quick summary of project patterns

-- Namespace layout: `Piplup\\Sanitize\\Core`, `Piplup\\Sanitize\\Escape`,
  `Piplup\\Sanitize\\Kses`, `Piplup\\Sanitize\\Utils`. Keep new code in one of these areas.
- Files use `declare(strict_types=1);` at the top — preserve this.
- Utilities are implemented as static, stateless classes with typed
  signatures (prefer native type hints and return types). Follow that style
  unless an instance is required.
- Sanitization uses explicit allow-lists (`ALLOWED_PROPERTIES`) and deny-lists
  (`DENIED_PROPERTIES`) constants where appropriate. Follow the same pattern
  for any whitelisting/blacklisting logic.
- Multi-byte safety uses `mb_*` functions and `Encoding::toUtf8()`.
- HTML parsing uses `DOMDocument` (not regex). CSS parsing is lightweight and
  stateful (balanced-paren scanning) — prefer simple, auditable parsers.
- Global helper functions are provided under `src/functions.php` and are
  guarded with `function_exists()` and optionally enabled via Composer
  `files` autoload. Avoid adding more globals unless justified.
- Tests mirror `src/` structure under `tests/` and use PHPUnit with
  `phpunit.xml` present.

## Conventions (code & comments)

- Style: follow PSR-12. Do not reformat unrelated files.
- Docblocks: use Full PHPDoc (PSR-5 style) for public classes and methods.
  - Class-level docblock: short summary + example usage when helpful.
  - Method-level docblock: short summary, `@param` and `@return` annotations,
    and `@throws` only when exceptions can be thrown.
- Type hints: prefer native scalar and object types; use PHPDoc for union types
  or more expressive descriptions.
- Error handling: prefer returning safe values (empty string, empty array,
  `false`) for sanitizers rather than throwing. If a method must throw, add
  `@throws` and document the conditions.
- Constants & arrays: keep keys normalized (lowercase string keys for CSS
  props, etc.). Expand allowlists by appending to the constant array and add
  tests for the new entries.

## Sanitization & security patterns

- Canonical flow: `sanitize on input` and `escape on output` — document this
  pattern in any example code you add.
- Input normalization: use `Encoding::toUtf8()` then `html_entity_decode()`
  to avoid obfuscated attacks.
- URL sanitization: prefer `UrlSanitizer::escUrl()` / `escUrlRaw()` as the
  single place for protocol filtering. Add new protocols only through
  explicit allowlists and tests.
- CSS sanitization: follow the existing approach — allowlist properties,
  permit vendor prefixes and custom properties, disallow `expression()`,
  `behavior:`, and reject `url()` with unsafe protocols. If adding parsing
  code, keep it small and well-tested.
- HTML filtering: use `Kses::filter()` and `AllowedHtml` presets. Avoid ad-hoc
  regex-based HTML filters.

## Tests & verification

- Add unit tests under `tests/` mirroring the `src/` subfolder for any
  behavior changes. Use data providers for multiple inputs.
- Run the full test suite locally before opening a PR:

```bash
composer install
./vendor/bin/phpunit
```

### When to run tests (rules for agents)

Follow these rules to avoid unnecessary local test runs while keeping quality high:

- **Run tests locally** when you change any code or behaviour:
  - Any edits under `src/` or `tests/`.
  - Changes to `composer.json`, `phpunit.xml`, CI config, or build scripts.
  - Adding or updating dependencies.
  - Public API changes (function/method signatures, removed behaviour).
  - Security-sensitive code (sanitizers, parsers, escapers).
  - Bug fixes and logic refactors.

- **Run targeted tests** for small or localised edits: run the single affected
  test file or use `--filter` to limit the scope.

```bash
./vendor/bin/phpunit tests/Sanitize/CssSanitizerTest.php
./vendor/bin/phpunit --filter CssSanitizer
```

- **Skip running tests locally** for documentation-only or non-functional edits:
  - Edits to `README.md`, `CONTRIBUTING.md`, `LICENSE`, `docs/`, or examples
    that do not modify `src/`.
  - Comments-only changes, markdown formatting, or copy fixes.

- **Exceptions & guidance**
  - If a documentation change updates code samples, configuration, or other
    runnable snippets, run the affected tests or a quick smoke test.
  - If unsure whether a change is docs-only, run a quick targeted test or the
    full suite.
  - All PRs run CI which includes the test suite; ensure CI is green before
    merging.
  - Mark docs-only PRs with a `docs:` prefix or include `[docs]` in the PR
    title/description to signal reviewers that local tests are not necessary.

These rules balance developer velocity and safety: skip local tests for true
docs-only edits, but run tests for anything that could affect behaviour or
delivery.

- When tests fail after a change, either fix the root cause or revert the
  change; do not silence failing tests.

## Editing workflow (agents and humans)

1. Plan: use the repo's TODO/plan system (or create a short plan) before
   making changes. Keep changes focused and small.
2. Make edits using the repository patch format (use `apply_patch` tooling in
   this environment). Keep the patch minimal and include a concise
   explanation.
3. Run unit tests. If adding new behaviour, add tests first when practical.
4. Update `README.md`, `CONTRIBUTING.md`, or `CHANGELOG.md` if public APIs
   or examples change.
5. Commit and open a PR against `main` with a clear title and changelog
   entry.

Notes for programmatic edits (agents):
- Use `apply_patch` with the project's patch format and preserve surrounding
  context. Do not attempt large automatic refactors.
- Avoid changing coding style globally (no wholesale formatting) — follow
  existing file style.
- When adding dependencies, prefer `require-dev` for tooling and explain
  rationale in the PR.

## Commit & PR conventions

- Branch names: `feat/...`, `fix/...`, `docs/...`, `chore/...`, `test/...`.
- Commit messages: use conventional commit-style brief summary:
  `<type>(<scope>): <short description>`
  Example: `fix(css): allow vendor-prefixed properties in CssSanitizer`
- PR body: include what changed, why, test plan, and any migration notes.

## Documentation & examples

- Keep `README.md` short and put long per-class API details into generated
  docs or `docs/` if needed.
- Add runnable examples to `README.md` for the most common flows (sanitize
  text, escape HTML, sanitize styles, sanitize URLs).
- Maintain `CONTRIBUTING.md` for coding style and PHPDoc guidance (PSR-12,
  PSR-5 style docs).

## When to escalate

- If a change introduces a security risk (XSS, RCE, incorrect sanitization),
  stop and open an issue tagged `security` and request a human reviewer.
- For API-breaking changes, open an issue first and propose a migration plan.

## Example PHPDoc templates

Class-level:

```php
/**
 * Short description of the class's responsibility.
 *
 * Longer description and usage notes when needed.
 *
 * @api
 */
final class MySanitizer { }
```

Method-level:

```php
/**
 * Sanitize a fragment suitable for an HTML attribute.
 *
 * @param string $input Raw input
 * @return string Cleaned string (may be empty)
 */
public static function sanitize(string $input): string {}
```

## References

- `README.md` — examples and project overview
- `CONTRIBUTING.md` — workflow, tests, PHPDoc decision
- `phpunit.xml` — testing config
- `src/` and `tests/` — canonical code and test patterns to follow

---

Follow this document when making changes. When in doubt, open an issue and
ask for a human review — security and correctness are higher priority than
landed automation.
