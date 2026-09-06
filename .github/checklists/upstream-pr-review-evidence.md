# Upstream PR Review Evidence

Record this artifact before requesting the first automated review and update it
after every review pass.

```text
local pre-PR readiness reviews:
  count:
  date, reviewer, commit range, reviewed files, outcome:
reviewed commit:
proposed push commit:
review-to-push diff:
  changed files:
  scope and platform map updated:
  targeted build/test rerun:
automated reviews:
  ID, author, date, exact head SHA, finding count, suppressed finding count:
  active and suppressed finding disposition:
  post-repair validation:
local cumulative review before cloud review:
  date, reviewer, exact SHA/range, reviewed files, outcome:
platform/install matrix for package, protocol, or subprocess-launch changes:
  platform, installation mode, child-process import path, result, skip rationale:
changed surface:
  default behavior:
  explicit override:
  failure path:
  local evidence:
reviewer suggestions independently verified:
review-cycle stop rule:
  first-review repairs audited as one coherent change: yes or no
  second-review blocker: yes or no
  review-stop: PASS or FAIL - maintainer direction required
small-diff review requested: yes or no
small-diff review scope, tool-call budget, and deadline:
review cancellation or timeout:
reviewer artifacts removed:
```
