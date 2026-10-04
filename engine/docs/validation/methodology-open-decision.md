# Physical benchmark: unresolved methodology decision

Recorded 2026-09-23, before the physical run. This note records a question.
It does not answer it, and nothing in the code or the registered rule changed.

## What is registered

`scripts/media_benchmark.py` registers the decision rule from the experiment
proposal:

- `PASS_WITHIN_POINTS = 5.0`
- `FAIL_BELOW_POINTS = 10.0`

The rule compares recall on the physical stick with the synthetic baseline in
`docs/performance/benchmark.csv`. It covers recall only. The `score` command
reports the gap as `recall_delta_points`. It does not print a verdict, so a
person applies the rule to that number.

## What is not registered

Someone proposed a second condition: the run fails if any false positive
reaches HIGH. **That condition has not been adopted.** The scorer does not
check it, and it is not part of the registered rule.

The question behind it is also open: **if a HIGH candidate's recovered bytes
are corrupt, is that a HIGH false positive?** Both answers can be defended, and
the answer changes what a HIGH false positive count means. This is for the
human experiment owner to decide. It is not an implementation choice.

## What has to happen before the physical run

If the experiment owner adopts the HIGH-FP condition, or defines how a corrupt
HIGH recovery is classified, they must record that change here **before** the
run. The record needs the date, who decided, the exact wording, and whether it
adds to the 5/10 rule or replaces part of it. A condition written down after
the numbers are known is not pre-registered, and the report has to say so.

If nothing is recorded, the physical run is judged by the 5/10 recall rule
alone. The report should list HIGH false positives as an observation, not as a
pass/fail condition.
