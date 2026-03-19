# CodeQL Maintainer Workflow for iccDEV

How to integrate CodeQL analysis into the iccDEV development workflow.

## CI Integration

### Existing Workflows

| Workflow | Trigger | Scope | Database |
|----------|---------|-------|----------|
| `ci-iccdev-codeql.yml` | Weekly schedule | master vs cfl comparison | Fresh per-run |
| `codeql-security-analysis.yml` | Push/PR | Comprehensive (42 queries) | Fresh per-run |

### PR Review Workflow

When reviewing a PR that modifies IccProfLib or IccXML:

```bash
# 1. Build database on the PR branch
git checkout pr-branch
gh codeql database create /tmp/codeql-db-pr \
  --language=cpp --overwrite \
  --command=".github/scripts/codeql-build.sh" \
  --source-root="$(git rev-parse --show-toplevel)"

# 2. Run maintainer queries (quick — 7 queries, ~30s)
for q in iccdev-describe-param-bounds iccdev-describe-null-array \
         iccdev-format-specifier iccdev-signed-unsigned-format \
         iccdev-uninitialized-constructor iccdev-wrong-variable-index \
         iccdev-dumplut-missing-arg; do
  gh codeql query run \
    iccanalyzer-lite/codeql-queries/${q}.ql \
    -d /tmp/codeql-db-pr --output=/tmp/${q}.bqrs
  echo "=== $q ==="
  gh codeql bqrs decode /tmp/${q}.bqrs --format=csv 2>/dev/null | tail -5
done

# 3. Compare against baseline (master branch)
gh codeql database create /tmp/codeql-db-master \
  --language=cpp --overwrite \
  --command=".github/scripts/codeql-build.sh" \
  --source-root="$(git rev-parse --show-toplevel)"
# Run same queries on master, diff the CSV outputs
```

## False Positive Management

### Known Informational Alerts (not bugs)

These alerts are expected and can be suppressed:

| Query | Location | Reason |
|-------|----------|--------|
| `icc/xml-all-attacks` | XML export paths | Intentional XML safety testing |
| `icc/xml-external-entity-attacks` | XML export paths | Intentional XXE testing |
| `cpp/iccanalyzer-security` | Analyzer code | Informational, not a bug |
| `cpp/icc-buffer-overflow` @ `IccTagParsers.h:172` | Tag parser | False positive — guarded by `idx < size` |
| `icc/injection-attacks` @ `IccAnalyzerLUT.cpp:110` | LUT analyzer | `SafeSnprintf` is internal with `__attribute__((format))` |

### Suppressing False Positives

For persistent false positives, add `// lgtm[query-id]` comments:

```cpp
// lgtm[icc/describe-param-bounds] - params validated in caller
m_params[2] = value;
```

Or configure exclusions in `codeql-config.yml`:

```yaml
paths-ignore:
  - 'test-profiles/**'
  - 'fuzz/**'
```

## Pattern Recognition Guide

### What Each Maintainer Query Finds

**iccdev-describe-param-bounds**: When you add a new `Describe()` method that
accesses indexed parameters, ensure you check the count first:

```cpp
// BAD — crashes if m_nParameters < 3
void CIccMyType::Describe(std::string &sDescription) {
  sprintf(buf, "a=%.4f b=%.4f c=%.4f", m_params[0], m_params[1], m_params[2]);
}

// GOOD — bounds check before access
void CIccMyType::Describe(std::string &sDescription) {
  if (m_nParameters >= 3)
    sprintf(buf, "a=%.4f b=%.4f c=%.4f", m_params[0], m_params[1], m_params[2]);
  else
    sDescription += "Invalid: insufficient parameters\n";
}
```

**iccdev-uninitialized-constructor**: When adding a new `CIcc*` class with scalar
members, always initialize them:

```cpp
// BAD — empty constructor, scalars contain garbage
CIccCfgSearchApply::CIccCfgSearchApply() { }

// GOOD — explicit initialization
CIccCfgSearchApply::CIccCfgSearchApply()
  : m_bUsePcc(false)
  , m_nLutType(icXformLutColor)
  , m_nInterp(icInterpLinear)
  , m_fMinRange(0.0)
  , m_fMaxRange(1.0)
  , m_bInitialSearch(false)
{ }
```

**iccdev-format-specifier**: Common format string mistakes:

```cpp
// BAD — %8f is width 8, not precision 8
sprintf(buf, "%8f", value);        // prints "1.234567" (width 8, 6 decimal default)

// GOOD — %.8f is precision 8
sprintf(buf, "%.8f", value);       // prints "1.23456789" (8 decimal places)

// BAD — %lf with no precision
sprintf(buf, "%lf", value);        // prints 6 decimal places (default)

// GOOD — explicit precision
sprintf(buf, "%.4lf", value);      // prints 4 decimal places
```

## Batch Analysis Workflow

For periodic security audits:

```bash
# Full 42-query analysis
gh codeql database analyze /tmp/codeql-db-iccdev \
  --format=sarif-latest \
  --output=/tmp/audit-$(date +%Y%m%d).sarif \
  --threads=0 \
  iccanalyzer-lite/codeql-queries/security-research-suite.qls

# Summary report
python3 -c "
import json
from collections import Counter
with open('/tmp/audit-$(date +%Y%m%d).sarif') as f:
    sarif = json.load(f)
counts = Counter()
severity = Counter()
for r in sarif['runs'][0]['results']:
    counts[r['ruleId']] += 1
    sev = r.get('properties', {}).get('problem.severity', 'unknown')
    severity[sev] += 1
print('=== Results by Severity ===')
for s, c in severity.most_common():
    print(f'  {s}: {c}')
print(f'\n=== Results by Rule (top 10) ===')
for rule, count in counts.most_common(10):
    print(f'  {count:4d}  {rule}')
print(f'\nTotal: {sum(counts.values())} findings across {len(counts)} rules')
"
```

## Database Refresh Policy

| Event | Action |
|-------|--------|
| New iccDEV commit | Rebuild database |
| New CFL patch | Run maintainer queries to verify fix |
| New CodeQL query added | Run against existing database |
| Quarterly audit | Full rebuild + full suite |

Databases persist at `/tmp/codeql-db-iccdev` and can be reused until the
source changes. A typical build takes ~60 seconds on 24 cores.
