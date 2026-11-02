# Turns a decision model's answers to decision-questions.json into a judge
# verdict with applygate's tier table, so the model states facts and the
# table decides. Input: {"facts": {name: probability of yes}, "tier":
# "protected"|"standard"|"disposable", "model": "..."}. $t holds a threshold
# per fact (default 0.5). A fact the model refused counts as yes.
def yes($f): (.facts[$f] // 1) >= ($t[$f] // 0.5);
def rank: {"allow": 0, "ask": 1, "block": 2}[.];
def max_verdict: max_by(rank);

(if .tier == "" or .tier == null then "protected" else .tier end) as $tier0
| (if $tier0 == "disposable" and yes("production_target") then "protected" else $tier0 end) as $tier
| (yes("preview_only") and (yes("weakens_guard") | not)) as $preview
| ([
    "allow",
    (if yes("prints_secret") then "ask" else empty end),
    (if yes("weakens_guard") then "ask" else empty end),
    (if yes("shared_history") then "block" else empty end),
    (if $preview then empty
     elif $tier == "protected" then
       (if yes("destroys") or yes("iac_apply") then "block"
        elif yes("changes_remote") then "ask" else empty end)
     elif $tier == "standard" then
       (if (yes("destroys") and yes("bulk")) or yes("iac_apply") then "ask" else empty end)
     else empty end)
  ] | max_verdict) as $v
| {verdict: $v,
   reason: ("\(.model) facts: " + ([.facts | to_entries[] | "\(.key)=\(.value)"] | join(" ")) + "; the tier table gives \($v) in a \($tier) environment. A decision model gives no explanation.")}
