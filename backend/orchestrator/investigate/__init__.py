"""Investigation loop components for the orchestrator.

Lightweight reasoning components that cooperate through the investigation
blackboard (`blackboard.py`):

- planner  (Mission + Investigation Planner): objective, phase, confidence,
  next objective
- analyst  (Evidence Analyzer): folds parser intelligence into the board
- knowledge (Knowledge Manager): what is missing + candidate actions
- selector (Action Selector): ranks candidates by value heuristics
- prompts  (system prompt): identity / objective / reasoning contract
"""