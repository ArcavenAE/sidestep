# kos Commit Conventions

## kos-specific actions (from KOS process cycle)

In addition to conventional commit types (feat, fix, docs, etc.),
use these kos action types when working with the knowledge graph:

- `harvest`: update nodes after a probe cycle completes
- `promote`: move a node to a higher confidence tier
- `graveyard`: move a node to graveyard (ruled out)
- `probe`: begin or continue an exploration
- `finding`: write a finding from a probe
- `schema`: update the node schema
- `charter`: update the charter document

### Format
`[action]: [node-ids affected] — [one line description]`

### No AI Attribution
Do not add "Generated with Claude Code", "Co-Authored-By: Claude", or any
AI attribution to commits. The human is the author.
