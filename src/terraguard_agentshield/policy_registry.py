from __future__ import annotations

from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

try:
    from importlib.resources.abc import Traversable
except ModuleNotFoundError:  # Python 3.10 compatibility
    from importlib.abc import Traversable

ROOT = Path(__file__).resolve().parents[2]
POLICY_DIR = ROOT / "policies"


class PolicyRegistryError(RuntimeError):
    pass


@dataclass(frozen=True)
class PolicyPack:
    id: str
    title: str
    description: str
    version: str | None = None
    rules: list[dict[str, Any]] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "version": self.version,
            "rules": self.rules or [],
        }


class PolicyRegistry:
    def __init__(self, root: Path | None = None) -> None:
        self.root = self._resolve_root(root)

    @staticmethod
    def _resolve_root(root: Path | None = None) -> Path | Traversable:
        if root is not None:
            return root.resolve()
        if POLICY_DIR.exists():
            return POLICY_DIR
        return resources.files("terraguard_agentshield").joinpath("policies")

    def list_policy_packs(self) -> list[dict[str, Any]]:
        packs = []
        if not self.root.exists():
            return packs
        for pack_dir in sorted(self.root.iterdir()):
            if not pack_dir.is_dir():
                continue
            metadata = self._load_metadata(pack_dir)
            if metadata:
                packs.append(metadata)
        return packs

    def get_policy_pack(self, pack_id: str) -> dict[str, Any]:
        pack_dir = self.root.joinpath(pack_id)
        if not pack_dir.exists() or not pack_dir.is_dir():
            raise PolicyRegistryError(f"Policy pack '{pack_id}' not found.")
        metadata = self._load_metadata(pack_dir)
        if metadata is None:
            raise PolicyRegistryError(f"Policy pack '{pack_id}' is invalid.")
        return metadata

    def _load_metadata(self, pack_dir: Path | Traversable) -> dict[str, Any] | None:
        policy_path = pack_dir.joinpath("policy.yaml")
        if not policy_path.exists():
            return None
        with policy_path.open("r", encoding="utf-8") as handle:
            payload = yaml.safe_load(handle)
        if not isinstance(payload, dict):
            return None
        metadata = payload.get("metadata", {})
        return {
            "id": metadata.get("id", pack_dir.name),
            "title": metadata.get("title"),
            "description": metadata.get("description"),
            "version": metadata.get("version"),
            "policy": payload,
        }

    def load_policy(self, pack_id: str) -> dict[str, Any]:
        pack = self.get_policy_pack(pack_id)
        policy = pack.get("policy")
        if not policy:
            raise PolicyRegistryError(f"Policy pack '{pack_id}' contains no policy data.")
        return policy

    def save_policy(self, pack_id: str, content: dict[str, Any]) -> None:
        if not isinstance(self.root, Path):
            raise PolicyRegistryError("Cannot save policies into packaged read-only policy data.")
        pack_dir = self.root / pack_id
        pack_dir.mkdir(parents=True, exist_ok=True)
        policy_path = pack_dir / "policy.yaml"
        with policy_path.open("w", encoding="utf-8") as handle:
            yaml.safe_dump(content, handle)
