# core/module_base.py
from typing import Protocol, Dict, Any, Optional

class ModuleResult(Dict):
    """Normalized module result structure."""
    pass

class ModuleContext(Dict):
    """Context passed between modules for data sharing."""
    pass

class ModuleInterface(Protocol):
    """
    Modules must expose:
      - name: str
      - run(target: str, config: Dict[str, Any], ctx: ModuleContext) -> ModuleResult
    """
    name: str

    def run(self, target: str, config: Dict[str, Any], ctx: ModuleContext) -> ModuleResult:
        ...
