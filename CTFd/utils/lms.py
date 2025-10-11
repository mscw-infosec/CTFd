import urllib.parse
from typing import Any, Dict, Optional
import os

import requests

from CTFd.cache import cache
from CTFd.utils.logging import log


class LMSUnavailable(Exception):
    pass

class SafeAttrs(dict):
    def __missing__(self, key):
        return None

@cache.memoize(timeout=5)
def get_lms_ctfd_data_for_email(email: str) -> Dict[str, Any]:
    """
    Fetch CtfdAccountData from LMS for a given user email.

    Expected JSON structure:
    {
      "active_attempt_task_ids": [int, ...],
      "attributes": { ... }
    }
    """
    base_url: Optional[str] = os.getenv("LMS_BASE_URL")
    token: Optional[str] = os.getenv("LMS_CTFD_TOKEN")

    if not base_url or not token:
        # Configuration missing
        raise LMSUnavailable("LMS is not configured (LMS_BASE_URL/LMS_CTFD_TOKEN)")

    # Ensure no trailing slash duplication
    base = base_url.rstrip("/")
    path_email = urllib.parse.quote(email, safe="")
    url = f"{base}/account/{path_email}/ctfd-data"
    headers = {
        "Accept": "application/json",
        "X-CTFd-Token": token,
    }
    try:
        resp = requests.get(url, headers=headers, timeout=5)
    except requests.RequestException as e:
        raise LMSUnavailable(str(e))

    if resp.status_code != 200:
        raise LMSUnavailable(f"LMS returned {resp.status_code}")

    try:
        data = resp.json()
    except Exception as e:
        raise LMSUnavailable(f"Invalid LMS JSON: {e}")

    # Normalize
    attr = data.get("attributes") or {}
    task_ids = data.get("active_attempt_task_ids") or []
    if not isinstance(attr, dict) or not isinstance(task_ids, list):
        raise LMSUnavailable("Invalid LMS payload structure")
    return {"attributes": attr, "active_attempt_task_ids": task_ids}


# ---- Safe boolean expression evaluation for attribute logic ----
import ast


class SafeEvalVisitor(ast.NodeVisitor):
    ALLOWED_NODES = (
        ast.Expression,
        ast.BoolOp,
        ast.BinOp,
        ast.UnaryOp,
        ast.Compare,
        ast.Name,
        ast.Load,
        ast.Constant,
        ast.And,
        ast.Or,
        ast.Not,
        ast.Eq,
        ast.NotEq,
        ast.In,
        ast.NotIn,
        ast.Gt,
        ast.GtE,
        ast.Lt,
        ast.LtE,
        ast.Subscript,
        ast.Index,
        ast.Str,
        ast.List,
        ast.Tuple,
        ast.Dict,
    )

    def __init__(self, names: Dict[str, Any]):
        self.names = names

    def visit_Name(self, node: ast.Name):
        if node.id not in self.names:
            # Missing variables are treated as Falsey None
            self.names[node.id] = None

    def generic_visit(self, node):
        if not isinstance(node, self.ALLOWED_NODES):
            raise ValueError(f"Disallowed expression: {type(node).__name__}")
        super().generic_visit(node)


def eval_attr_logic(expression: str, attributes: Dict[str, Any]) -> bool:
    """
    Evaluate a safe Python-like boolean expression against the attributes dict.
    Example: '(role == "pro") or (department == "infosec" and level >= 3)'

    Variables correspond to keys in the attributes mapping.
    Missing variables evaluate as None.
    """
    if not expression or not expression.strip():
        return True  # No expression provided => allow

    try:
        tree = ast.parse(expression, mode="eval")
        SafeEvalVisitor(attributes.copy()).visit(tree)
        compiled = compile(tree, filename="<attr-logic>", mode="eval")
        # Evaluate with empty builtins for safety
        result = eval(compiled, {"__builtins__": {}}, SafeAttrs(attributes))
        return bool(result)
    except Exception as e:
        log("owl", "Error evaluating LMS attribute expression: {err}", err=e)
        # On any error, deny by default for safety
        return False
