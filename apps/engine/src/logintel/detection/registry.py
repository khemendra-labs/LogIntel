"""In-memory thread-safe registry for validated detection rules."""

import threading
from typing import Dict, Iterable, List, Optional, Union

from logintel.detection.errors import DuplicateRuleError
from logintel.detection.models import DetectionRule, RuleCategory


class RuleRegistry:
    """In-memory catalog of validated detection rules.
    
    Guarantees:
    - Deterministic index by unique rule ID.
    - Zero silent overwrites (DuplicateRuleError on conflict).
    - Separation between enabled and disabled rules.
    - Thread safety under concurrent reads and registrations.
    """

    def __init__(self) -> None:
        self._rules: Dict[str, DetectionRule] = {}
        self._lock = threading.RLock()

    def register(self, rule: DetectionRule) -> None:
        """Register a single validated rule.
        
        Raises:
            DuplicateRuleError: If a rule with the same ID already exists in the registry.
        """
        with self._lock:
            if rule.id in self._rules:
                raise DuplicateRuleError(rule.id)
            self._rules[rule.id] = rule

    def register_many(self, rules: Iterable[DetectionRule]) -> int:
        """Atomically register multiple rules.
        
        Validates for duplicates within the batch and against the registry before committing.
        
        Returns:
            Number of registered rules.
        """
        rules_list = list(rules)
        with self._lock:
            # Check for intra-batch duplicates
            seen_ids = set()
            for r in rules_list:
                if r.id in seen_ids:
                    raise DuplicateRuleError(r.id)
                seen_ids.add(r.id)
                if r.id in self._rules:
                    raise DuplicateRuleError(r.id)

            # Commit all
            for r in rules_list:
                self._rules[r.id] = r

        return len(rules_list)

    def get(self, rule_id: str) -> Optional[DetectionRule]:
        """Look up a rule by ID."""
        with self._lock:
            return self._rules.get(rule_id)

    def list_rules(self) -> List[DetectionRule]:
        """Return all registered rules sorted by rule ID."""
        with self._lock:
            return [self._rules[k] for k in sorted(self._rules.keys())]

    def get_enabled_rules(self) -> List[DetectionRule]:
        """Return all enabled rules sorted by rule ID."""
        with self._lock:
            return [r for k, r in sorted(self._rules.items()) if r.enabled]

    def get_rules_by_category(self, category: Union[RuleCategory, str]) -> List[DetectionRule]:
        """Filter rules by category."""
        cat_val = category.value if isinstance(category, RuleCategory) else str(category)
        with self._lock:
            return [r for k, r in sorted(self._rules.items()) if r.category.value == cat_val]

    def count(self) -> int:
        """Return total count of registered rules."""
        with self._lock:
            return len(self._rules)

    def __len__(self) -> int:
        return self.count()

    def clear(self) -> None:
        """Remove all rules from registry."""
        with self._lock:
            self._rules.clear()


_DEFAULT_REGISTRY: Optional[RuleRegistry] = None
_REGISTRY_LOCK = threading.Lock()


def get_rule_registry() -> RuleRegistry:
    """Retrieve or lazily initialize the default singleton RuleRegistry."""
    global _DEFAULT_REGISTRY
    if _DEFAULT_REGISTRY is None:
        with _REGISTRY_LOCK:
            if _DEFAULT_REGISTRY is None:
                from logintel.detection.loader import load_default_rules
                reg = RuleRegistry()
                rules = load_default_rules()
                reg.register_many(rules)
                _DEFAULT_REGISTRY = reg
    return _DEFAULT_REGISTRY

