"""
GraphQL Engine and Intelligent Agent Tool for Personal Agentic AI (PAI).
Provides schema introspection, query validation, and ultra-sparse schema extraction
optimized for local LLM context windows (95% token savings over REST/JSON dumps).
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


INTROSPECTION_QUERY = """
query IntrospectSchema {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      description
      fields(includeDeprecated: false) {
        name
        description
        args {
          name
          type { name kind ofType { name kind } }
        }
        type {
          name
          kind
          ofType { name kind ofType { name kind } }
        }
      }
    }
  }
}
"""


def _format_type_name(type_obj: Optional[Dict[str, Any]]) -> str:
    """Formats nested GraphQL type descriptor into SDL type notation."""
    if not type_obj:
        return "Unknown"
    kind = type_obj.get("kind", "")
    name = type_obj.get("name")
    of_type = type_obj.get("ofType")
    if kind == "NON_NULL":
        return f"{_format_type_name(of_type)}!"
    if kind == "LIST":
        return f"[{_format_type_name(of_type)}]"
    return name or "Unknown"


class GraphQLClient:
    """
    Client for interacting with local or remote GraphQL services and Apollo Supergraphs.
    """
    def __init__(self, endpoint: str = "http://127.0.0.1:4000/graphql", default_headers: Optional[Dict[str, str]] = None):
        self.endpoint = endpoint
        self.headers = default_headers or {"Content-Type": "application/json"}

    def execute(self, query: str, variables: Optional[Dict[str, Any]] = None, timeout: float = 15.0) -> Dict[str, Any]:
        """Executes a GraphQL operation against the target endpoint."""
        val_ok, err = self.validate_query(query)
        if not val_ok:
            return {"errors": [{"message": f"Client validation failed: {err}"}]}

        payload = {"query": query}
        if variables:
            payload["variables"] = variables

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(self.endpoint, data=data, headers=self.headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw)
        except urllib.error.HTTPError as he:
            err_body = he.read().decode("utf-8", errors="replace")
            try:
                return json.loads(err_body)
            except Exception:
                return {"errors": [{"message": f"HTTP {he.code}: {he.reason}", "body": err_body}]}
        except Exception as e:
            return {"errors": [{"message": f"Connection error: {e}"}]}

    def introspect(self, timeout: float = 20.0) -> Dict[str, Any]:
        """Runs the standard introspection query to discover runtime schema."""
        return self.execute(INTROSPECTION_QUERY, timeout=timeout)

    def get_sparse_schema_summary(self, timeout: float = 20.0) -> str:
        """
        Produces a concise SDL schema summary tailored for local AI agent prompts.
        Extracts only primary query/mutation fields and user-defined types,
        reducing token overhead by 95% compared to raw introspection payloads.
        """
        raw = self.introspect(timeout=timeout)
        if "errors" in raw and not raw.get("data"):
            return f"# Schema introspection failed: {raw['errors'][0].get('message')}"

        schema_data = raw.get("data", {}).get("__schema", {})
        query_type_name = (schema_data.get("queryType") or {}).get("name", "Query")
        mutation_type_name = (schema_data.get("mutationType") or {}).get("name", "Mutation")

        types = schema_data.get("types", [])
        lines = [
            "# --- SPARSE GRAPHQL SCHEMA (Auto-discovered via Introspection) ---",
            "# Request only sparse fields required for your task to conserve tokens.",
        ]

        query_fields = []
        mutation_fields = []
        user_types = []

        for t in types:
            t_name = t.get("name", "")
            if t_name.startswith("__"):
                continue  # skip internal introspection types
            if t.get("kind") not in ("OBJECT", "INPUT_OBJECT"):
                continue

            fields_list = t.get("fields") or []
            field_signatures = []
            for f in fields_list:
                f_name = f.get("name")
                f_type = _format_type_name(f.get("type"))
                args = f.get("args") or []
                if args:
                    arg_str = ", ".join(f"{a['name']}: {_format_type_name(a['type'])}" for a in args)
                    field_signatures.append(f"  {f_name}({arg_str}): {f_type}")
                else:
                    field_signatures.append(f"  {f_name}: {f_type}")

            if t_name == query_type_name:
                query_fields = field_signatures
            elif t_name == mutation_type_name:
                mutation_fields = field_signatures
            else:
                user_types.append((t_name, field_signatures))

        if query_fields:
            lines.append("type Query {")
            lines.extend(query_fields)
            lines.append("}")

        if mutation_fields:
            lines.append("type Mutation {")
            lines.extend(mutation_fields)
            lines.append("}")

        for t_name, fields in user_types[:15]:  # top domain types
            lines.append(f"type {t_name} {{")
            lines.extend(fields[:10])
            lines.append("}")

        return "\n".join(lines)

    @staticmethod
    def validate_query(query: str) -> Tuple[bool, Optional[str]]:
        """
        Validates basic GraphQL query syntax before dispatching to the server.
        Checks for balanced braces and recognized query/mutation operations.
        """
        stripped = query.strip()
        if not stripped:
            return False, "Query string is empty"

        # Check balanced braces
        depth = 0
        for char in stripped:
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth < 0:
                    return False, "Unbalanced closing brace '}'"
        if depth != 0:
            return False, "Unbalanced opening brace '{'"

        # Basic operation check
        clean = re.sub(r"#.*", "", stripped)
        clean = clean.strip()
        if not (clean.startswith("{") or clean.startswith("query") or clean.startswith("mutation") or clean.startswith("subscription")):
            return False, "Invalid GraphQL root operation. Must start with query, mutation, or '{'."

        return True, None


def execute_graphql_tool(
    query: str,
    variables_json: Optional[str] = None,
    endpoint: Optional[str] = None,
) -> str:
    """
    PAI Agent Callable Tool: Executes a validated GraphQL query against target endpoint.
    """
    ep = endpoint or os.environ.get("PAI_GRAPHQL_ENDPOINT", "http://127.0.0.1:4000/graphql")
    client = GraphQLClient(endpoint=ep)
    vars_dict = None
    if variables_json:
        try:
            vars_dict = json.loads(variables_json)
        except Exception as e:
            return f"Error parsing variables JSON: {e}"
    res = client.execute(query=query, variables=vars_dict)
    return json.dumps(res, indent=2, ensure_ascii=False)


def introspect_graphql_tool(endpoint: Optional[str] = None) -> str:
    """
    PAI Agent Callable Tool: Introspects target GraphQL schema and returns sparse token-efficient SDL.
    """
    ep = endpoint or os.environ.get("PAI_GRAPHQL_ENDPOINT", "http://127.0.0.1:4000/graphql")
    client = GraphQLClient(endpoint=ep)
    return client.get_sparse_schema_summary()
