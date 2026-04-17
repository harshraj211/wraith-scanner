"""Cross-file taint analysis for Python and JavaScript repositories."""
from __future__ import annotations

import ast
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

try:  # pragma: no cover - optional parser dependency
    import esprima
except Exception:  # pragma: no cover
    esprima = None


PYTHON_ROUTE_DECORATORS = ("route", "get", "post", "put", "patch", "delete", "api_view")
REQUEST_SOURCE_HINTS = (
    "request.args",
    "request.form",
    "request.values",
    "request.json",
    "request.data",
    "request.GET",
    "request.POST",
    "request.headers",
    "request.cookies",
    "req.query",
    "req.body",
    "req.params",
    "req.headers",
    "req.cookies",
)

SINK_RULES: List[Tuple[re.Pattern[str], str, str, str]] = [
    (re.compile(r"(^|\.)(execute|executemany|executescript|raw|query)$"), "sqli", "A03:2021", "CWE-89"),
    (re.compile(r"(^|\.)(system|popen|spawn|exec|eval|call|check_output|run)$"), "command-injection", "A03:2021", "CWE-78"),
    (re.compile(r"(^|\.)(open|read_text|write_text|send_file|send_from_directory|readfile|readfilesync)$"), "path-traversal", "A01:2021", "CWE-22"),
    (re.compile(r"(^|\.)(request|get|post|put|patch|delete|urlopen|fetch)$"), "ssrf", "A10:2021", "CWE-918"),
    (re.compile(r"(^|\.)(render_template_string|send|write|end)$"), "xss", "A03:2021", "CWE-79"),
    (re.compile(r"(^|\.)(Template|Environment|render|render_string)$"), "ssti", "A03:2021", "CWE-1336"),
]

SANITIZER_HINTS = (
    "sanitize",
    "escape",
    "clean",
    "bleach.clean",
    "html.escape",
    "markupsafe.escape",
    "uuid.UUID",
    "ObjectId",
    "parseInt",
    "Number",
    "shlex.quote",
    "secure_filename",
    "int",
    "float",
    "bool",
)

ROLE_ENTRYPOINT_HINTS = ("route", "view", "controller", "handler", "api")
JS_ROUTE_METHODS = {"get", "post", "put", "patch", "delete", "use"}


@dataclass(frozen=True)
class CallFrame:
    symbol: str
    file: str
    line: int
    role: str

    def render(self) -> str:
        return f"{self.role}: {self.symbol} ({self.file}:{self.line})"


@dataclass
class FunctionInfo:
    language: str
    name: str
    qualname: str
    module: str
    file: str
    line: int
    params: List[str]
    node: Any
    imports: Dict[str, str] = field(default_factory=dict)
    decorators: List[str] = field(default_factory=list)
    is_entrypoint: bool = False


class TaintAnalyzer:
    """Repo-wide taint analysis that follows sources to sinks across files."""

    def __init__(self) -> None:
        self.repo_root = ""
        self.findings: List[Dict[str, Any]] = []
        self.functions: Dict[str, FunctionInfo] = {}
        self._simple_index: Dict[Tuple[str, str], List[str]] = {}
        self._active_states: Set[Tuple[str, Tuple[str, ...]]] = set()
        self._return_cache: Dict[Tuple[str, Tuple[str, ...]], bool] = {}

    def scan_repo(
        self,
        repo_path: str,
        file_tree: Dict[str, List[str]],
        tech_stack: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        self.repo_root = repo_path
        self.findings = []
        self.functions = {}
        self._simple_index = {}
        self._active_states = set()
        self._return_cache = {}

        python_files = list(file_tree.get("python", []) or [])
        js_files = [*list(file_tree.get("javascript", []) or []), *self._typescript_candidates(file_tree)]

        for path in python_files:
            self._index_python_file(path)
        for path in js_files:
            self._index_js_file(path)

        entrypoints = [func for func in self.functions.values() if func.is_entrypoint]
        for entry in entrypoints:
            frame = CallFrame(entry.qualname, entry.file, entry.line, "entrypoint")
            tainted_params = self._entry_tainted_params(entry)
            self._analyze_function(entry, tainted_params, [frame])

        return self._dedupe_findings(self.findings)

    def _typescript_candidates(self, file_tree: Dict[str, List[str]]) -> List[str]:
        candidates: List[str] = []
        for path in file_tree.get("all", []) or []:
            if str(path).lower().endswith((".ts", ".tsx")):
                candidates.append(path)
        return candidates

    def _dedupe_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        unique: List[Dict[str, Any]] = []
        seen = set()
        for finding in findings:
            key = (
                finding.get("file"),
                finding.get("line"),
                finding.get("type"),
                tuple(finding.get("taint_path", []) or []),
            )
            if key in seen:
                continue
            seen.add(key)
            unique.append(finding)
        return unique

    def _register_function(self, func: FunctionInfo) -> None:
        self.functions[func.qualname] = func
        self._simple_index.setdefault((func.language, func.name), []).append(func.qualname)

    def _relative(self, path: str) -> str:
        try:
            return str(Path(path).resolve().relative_to(Path(self.repo_root).resolve()))
        except Exception:
            return str(path)

    def _module_name_from_path(self, path: str) -> str:
        rel = self._relative(path).replace("\\", "/")
        if rel.endswith(".py"):
            rel = rel[:-3]
        elif rel.endswith(".js"):
            rel = rel[:-3]
        elif rel.endswith(".jsx"):
            rel = rel[:-4]
        elif rel.endswith(".ts"):
            rel = rel[:-3]
        elif rel.endswith(".tsx"):
            rel = rel[:-4]
        rel = rel.replace("/", ".")
        if rel.endswith(".__init__"):
            rel = rel[: -len(".__init__")]
        return rel

    def _entry_tainted_params(self, func: FunctionInfo) -> List[str]:
        tainted: List[str] = []
        for param in func.params:
            lowered = param.lower()
            if lowered in {"request", "req", "body", "params", "query"}:
                tainted.append(param)
        return tainted

    def _analyze_function(
        self,
        func: FunctionInfo,
        tainted_params: Sequence[str],
        call_stack: List[CallFrame],
    ) -> bool:
        state_key = (func.qualname, tuple(sorted(set(tainted_params))))
        if state_key in self._return_cache:
            return self._return_cache[state_key]
        if state_key in self._active_states or len(call_stack) > 8:
            return False

        self._active_states.add(state_key)
        try:
            if func.language == "python":
                result = self._analyze_python_function(func, set(tainted_params), call_stack)
            else:
                result = self._analyze_js_function(func, set(tainted_params), call_stack)
            self._return_cache[state_key] = result
            return result
        finally:
            self._active_states.discard(state_key)

    # ------------------------------------------------------------------
    # Python indexing
    # ------------------------------------------------------------------

    def _index_python_file(self, path: str) -> None:
        try:
            source = Path(path).read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source, filename=path)
        except Exception:
            return

        module = self._module_name_from_path(path)
        imports = self._python_collect_imports(tree, module)
        self._python_collect_functions(tree.body, module, self._relative(path), imports, class_stack=[])

    def _python_collect_imports(self, tree: ast.AST, module: str) -> Dict[str, str]:
        imports: Dict[str, str] = {}
        for node in getattr(tree, "body", []):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports[alias.asname or alias.name.split(".")[-1]] = alias.name
            elif isinstance(node, ast.ImportFrom):
                base = self._resolve_relative_module(module, node.module, node.level)
                for alias in node.names:
                    imports[alias.asname or alias.name] = f"{base}.{alias.name}" if base else alias.name
        return imports

    def _resolve_relative_module(self, current_module: str, target_module: Optional[str], level: int) -> str:
        if level <= 0:
            return target_module or ""
        parts = current_module.split(".")
        if current_module:
            parts = parts[:-1]
        if level > 1:
            parts = parts[: -(level - 1)] if len(parts) >= level - 1 else []
        if target_module:
            parts.append(target_module)
        return ".".join(part for part in parts if part)

    def _python_collect_functions(
        self,
        nodes: Iterable[ast.stmt],
        module: str,
        rel_path: str,
        imports: Dict[str, str],
        class_stack: List[str],
    ) -> None:
        for node in nodes:
            if isinstance(node, ast.ClassDef):
                self._python_collect_functions(node.body, module, rel_path, imports, class_stack + [node.name])
                continue
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            name = node.name
            qual_parts = [module] if module else []
            qual_parts.extend(class_stack)
            qual_parts.append(name)
            decorators = [self._python_name_of(dec) for dec in node.decorator_list if self._python_name_of(dec)]

            params = [arg.arg for arg in node.args.args]
            func = FunctionInfo(
                language="python",
                name=name,
                qualname=".".join(qual_parts),
                module=module,
                file=rel_path,
                line=getattr(node, "lineno", 1),
                params=params,
                node=node,
                imports=dict(imports),
                decorators=decorators,
                is_entrypoint=self._is_python_entrypoint(rel_path, decorators, node),
            )
            self._register_function(func)

    def _is_python_entrypoint(self, rel_path: str, decorators: List[str], node: ast.AST) -> bool:
        for decorator in decorators:
            lowered = decorator.lower()
            if any(token in lowered for token in PYTHON_ROUTE_DECORATORS):
                return True

        rel_lower = rel_path.lower()
        if any(hint in rel_lower for hint in ROLE_ENTRYPOINT_HINTS):
            for child in ast.walk(node):
                if self._is_python_source_expr(child):
                    return True
        return False

    # ------------------------------------------------------------------
    # Python analysis
    # ------------------------------------------------------------------

    def _analyze_python_function(
        self,
        func: FunctionInfo,
        tainted: Set[str],
        call_stack: List[CallFrame],
    ) -> bool:
        return self._analyze_python_block(func, list(func.node.body), set(tainted), call_stack)

    def _analyze_python_block(
        self,
        func: FunctionInfo,
        statements: List[ast.stmt],
        tainted: Set[str],
        call_stack: List[CallFrame],
    ) -> bool:
        return_tainted = False

        for stmt in statements:
            if isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                value = stmt.value if not isinstance(stmt, ast.AugAssign) else stmt.value
                expr_tainted = self._python_expr_tainted(func, value, tainted, call_stack)
                targets = []
                if isinstance(stmt, ast.Assign):
                    for target in stmt.targets:
                        targets.extend(self._python_target_names(target))
                else:
                    targets.extend(self._python_target_names(stmt.target))

                for target_name in targets:
                    if expr_tainted:
                        tainted.add(target_name)
                    else:
                        tainted.discard(target_name)
                continue

            if isinstance(stmt, ast.Return):
                if self._python_expr_tainted(func, stmt.value, tainted, call_stack):
                    return_tainted = True
                continue

            if isinstance(stmt, ast.Expr):
                self._python_expr_tainted(func, stmt.value, tainted, call_stack)
                continue

            if isinstance(stmt, ast.If):
                body_tainted = set(tainted)
                else_tainted = set(tainted)
                body_ret = self._analyze_python_block(func, list(stmt.body), body_tainted, call_stack)
                else_ret = self._analyze_python_block(func, list(stmt.orelse), else_tainted, call_stack)
                tainted |= body_tainted | else_tainted
                return_tainted = return_tainted or body_ret or else_ret
                continue

            if isinstance(stmt, (ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith)):
                nested_tainted = set(tainted)
                if hasattr(stmt, "body"):
                    return_tainted = return_tainted or self._analyze_python_block(
                        func, list(stmt.body), nested_tainted, call_stack
                    )
                    tainted |= nested_tainted
                if hasattr(stmt, "orelse"):
                    orelse_tainted = set(tainted)
                    return_tainted = return_tainted or self._analyze_python_block(
                        func, list(stmt.orelse), orelse_tainted, call_stack
                    )
                    tainted |= orelse_tainted
                continue

            if isinstance(stmt, ast.Try):
                for bucket in (stmt.body, stmt.orelse, stmt.finalbody):
                    nested_tainted = set(tainted)
                    return_tainted = return_tainted or self._analyze_python_block(
                        func, list(bucket), nested_tainted, call_stack
                    )
                    tainted |= nested_tainted
                for handler in stmt.handlers:
                    nested_tainted = set(tainted)
                    return_tainted = return_tainted or self._analyze_python_block(
                        func, list(handler.body), nested_tainted, call_stack
                    )
                    tainted |= nested_tainted

        return return_tainted

    def _python_target_names(self, target: ast.AST) -> List[str]:
        if isinstance(target, ast.Name):
            return [target.id]
        if isinstance(target, (ast.Tuple, ast.List)):
            out: List[str] = []
            for item in target.elts:
                out.extend(self._python_target_names(item))
            return out
        if isinstance(target, ast.Attribute):
            name = self._python_name_of(target)
            return [name] if name else []
        return []

    def _python_expr_tainted(
        self,
        func: FunctionInfo,
        node: Optional[ast.AST],
        tainted: Set[str],
        call_stack: List[CallFrame],
    ) -> bool:
        if node is None:
            return False
        if self._is_python_source_expr(node):
            return True

        if isinstance(node, ast.Name):
            return node.id in tainted

        if isinstance(node, ast.Attribute):
            name = self._python_name_of(node)
            if name and any(source in name for source in REQUEST_SOURCE_HINTS):
                return True
            return self._python_expr_tainted(func, node.value, tainted, call_stack)

        if isinstance(node, ast.Subscript):
            name = self._python_name_of(node.value)
            if name and any(source in name for source in REQUEST_SOURCE_HINTS):
                return True
            return self._python_expr_tainted(func, node.value, tainted, call_stack) or self._python_expr_tainted(
                func, node.slice, tainted, call_stack
            )

        if isinstance(node, ast.Call):
            return self._python_call_tainted(func, node, tainted, call_stack)

        if isinstance(node, ast.JoinedStr):
            return any(self._python_expr_tainted(func, value, tainted, call_stack) for value in node.values)

        if isinstance(node, (ast.BinOp, ast.BoolOp, ast.Compare)):
            children = [child for child in ast.iter_child_nodes(node)]
            return any(self._python_expr_tainted(func, child, tainted, call_stack) for child in children)

        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return any(self._python_expr_tainted(func, elt, tainted, call_stack) for elt in node.elts)

        if isinstance(node, ast.Dict):
            return any(
                self._python_expr_tainted(func, key, tainted, call_stack)
                or self._python_expr_tainted(func, value, tainted, call_stack)
                for key, value in zip(node.keys, node.values)
            )

        return any(self._python_expr_tainted(func, child, tainted, call_stack) for child in ast.iter_child_nodes(node))

    def _is_python_source_expr(self, node: ast.AST) -> bool:
        name = self._python_name_of(node)
        if name and any(source in name for source in REQUEST_SOURCE_HINTS):
            return True

        if isinstance(node, ast.Call):
            call_name = self._python_name_of(node.func)
            if call_name in {"input", "os.getenv", "getenv"}:
                return True
            if call_name and any(source in call_name for source in REQUEST_SOURCE_HINTS):
                return True
        return False

    def _python_call_tainted(
        self,
        func: FunctionInfo,
        node: ast.Call,
        tainted: Set[str],
        call_stack: List[CallFrame],
    ) -> bool:
        call_name = self._python_call_name(func, node.func)
        if self._is_sanitizer(call_name):
            return False

        args = list(node.args) + [kw.value for kw in node.keywords if kw.value is not None]
        arg_taints = [self._python_expr_tainted(func, arg, tainted, call_stack) for arg in args]

        sink = self._match_sink(call_name)
        if sink and any(arg_taints):
            self._record_finding(func, call_stack, call_name, node.lineno, sink)

        resolved = self._resolve_python_function(func, call_name)
        if resolved:
            callee_tainted = []
            for idx, param in enumerate(resolved.params):
                if idx < len(arg_taints) and arg_taints[idx]:
                    callee_tainted.append(param)
            for kw in node.keywords:
                if kw.arg and kw.arg in resolved.params and self._python_expr_tainted(func, kw.value, tainted, call_stack):
                    callee_tainted.append(kw.arg)

            if callee_tainted:
                frame = CallFrame(resolved.qualname, resolved.file, resolved.line, "call")
                nested_stack = call_stack + [frame]
                nested_return = self._analyze_function(resolved, callee_tainted, nested_stack)
                if nested_return:
                    return True

        if any(arg_taints):
            return True

        return False

    def _resolve_python_function(self, current_func: FunctionInfo, call_name: str) -> Optional[FunctionInfo]:
        if not call_name:
            return None
        if call_name in self.functions:
            return self.functions[call_name]
        if call_name in current_func.imports:
            imported = current_func.imports[call_name]
            if imported in self.functions:
                return self.functions[imported]
        if "." not in call_name:
            direct = f"{current_func.module}.{call_name}" if current_func.module else call_name
            if direct in self.functions:
                return self.functions[direct]
        simple_matches = self._simple_index.get(("python", call_name.split(".")[-1]), [])
        if len(simple_matches) == 1:
            return self.functions.get(simple_matches[0])
        return None

    def _python_name_of(self, node: Optional[ast.AST]) -> str:
        if node is None:
            return ""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = self._python_name_of(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        if isinstance(node, ast.Call):
            return self._python_name_of(node.func)
        if isinstance(node, ast.Subscript):
            return self._python_name_of(node.value)
        try:
            return ast.unparse(node)
        except Exception:
            return ""

    def _python_call_name(self, func: FunctionInfo, node: ast.AST) -> str:
        raw = self._python_name_of(node)
        if raw in func.imports:
            return func.imports[raw]
        if "." in raw:
            head, tail = raw.split(".", 1)
            if head in func.imports:
                return f"{func.imports[head]}.{tail}"
        return raw

    # ------------------------------------------------------------------
    # JavaScript indexing
    # ------------------------------------------------------------------

    def _index_js_file(self, path: str) -> None:
        if esprima is None:  # pragma: no cover - optional dependency
            return

        try:
            source = Path(path).read_text(encoding="utf-8", errors="ignore")
            program = esprima.parseModule(source, {"loc": True, "tolerant": True}).toDict()
        except Exception:
            try:
                program = esprima.parseScript(source, {"loc": True, "tolerant": True}).toDict()
            except Exception:
                return

        module = self._module_name_from_path(path)
        rel_path = self._relative(path)
        imports = self._js_collect_imports(program, module)
        self._js_collect_functions(program.get("body", []), module, rel_path, imports)
        self._js_mark_entrypoints(program, module, rel_path, imports)

    def _js_collect_imports(self, program: Dict[str, Any], module: str) -> Dict[str, str]:
        imports: Dict[str, str] = {}
        for stmt in program.get("body", []) or []:
            if stmt.get("type") == "ImportDeclaration":
                source = self._js_resolve_local_module(module, (stmt.get("source") or {}).get("value"))
                for spec in stmt.get("specifiers", []) or []:
                    local = ((spec.get("local") or {}).get("name")) or ""
                    imported = ((spec.get("imported") or {}).get("name")) or local
                    imports[local] = f"{source}.{imported}" if source and imported else source
            if stmt.get("type") != "VariableDeclaration":
                continue
            for decl in stmt.get("declarations", []) or []:
                init = decl.get("init") or {}
                if init.get("type") != "CallExpression":
                    continue
                callee = self._js_member_name(init.get("callee"))
                if callee != "require":
                    continue
                args = init.get("arguments", []) or []
                if not args:
                    continue
                source = self._js_resolve_local_module(module, (args[0] or {}).get("value"))
                if not source:
                    continue
                ident = decl.get("id") or {}
                if ident.get("type") == "Identifier":
                    imports[ident.get("name")] = source
                elif ident.get("type") == "ObjectPattern":
                    for prop in ident.get("properties", []) or []:
                        key = ((prop.get("key") or {}).get("name")) or ""
                        value = ((prop.get("value") or {}).get("name")) or key
                        if key:
                            imports[value] = f"{source}.{key}"
        return imports

    def _js_resolve_local_module(self, current_module: str, raw: Optional[str]) -> str:
        if not raw or not str(raw).startswith("."):
            return ""
        current_dir = current_module.rsplit(".", 1)[0] if "." in current_module else ""
        parts = [part for part in current_dir.split(".") if part]
        for piece in str(raw).split("/"):
            if piece in {"", "."}:
                continue
            if piece == "..":
                if parts:
                    parts.pop()
            else:
                parts.append(piece)
        return ".".join(parts)

    def _js_collect_functions(
        self,
        body: List[Dict[str, Any]],
        module: str,
        rel_path: str,
        imports: Dict[str, str],
    ) -> None:
        for stmt in body:
            stype = stmt.get("type")
            if stype == "FunctionDeclaration":
                name = ((stmt.get("id") or {}).get("name")) or ""
                if name:
                    self._register_function(
                        FunctionInfo(
                            language="javascript",
                            name=name,
                            qualname=f"{module}.{name}" if module else name,
                            module=module,
                            file=rel_path,
                            line=self._js_line(stmt),
                            params=[param.get("name", "") for param in stmt.get("params", []) if param.get("name")],
                            node=stmt,
                            imports=dict(imports),
                        )
                    )
            elif stype == "VariableDeclaration":
                for decl in stmt.get("declarations", []) or []:
                    init = decl.get("init") or {}
                    if init.get("type") not in {"ArrowFunctionExpression", "FunctionExpression"}:
                        continue
                    ident = decl.get("id") or {}
                    name = ident.get("name") or ""
                    if not name:
                        continue
                    self._register_function(
                        FunctionInfo(
                            language="javascript",
                            name=name,
                            qualname=f"{module}.{name}" if module else name,
                            module=module,
                            file=rel_path,
                            line=self._js_line(decl),
                            params=[param.get("name", "") for param in init.get("params", []) if param.get("name")],
                            node=init,
                            imports=dict(imports),
                        )
                    )
            elif stype == "ExportNamedDeclaration":
                declaration = stmt.get("declaration") or {}
                self._js_collect_functions([declaration], module, rel_path, imports)

    def _js_mark_entrypoints(
        self,
        program: Dict[str, Any],
        module: str,
        rel_path: str,
        imports: Dict[str, str],
    ) -> None:
        for node in self._walk_js_nodes(program):
            if node.get("type") != "CallExpression":
                continue
            callee = self._js_member_name(node.get("callee"), imports)
            if not callee:
                continue
            method = callee.split(".")[-1].lower()
            root = callee.split(".")[0].lower()
            if method not in JS_ROUTE_METHODS or root not in {"app", "router"}:
                continue

            for arg in node.get("arguments", []) or []:
                atype = arg.get("type")
                if atype in {"FunctionExpression", "ArrowFunctionExpression"}:
                    name = f"route_{method}_{self._js_line(arg)}"
                    qualname = f"{module}.{name}" if module else name
                    func = FunctionInfo(
                        language="javascript",
                        name=name,
                        qualname=qualname,
                        module=module,
                        file=rel_path,
                        line=self._js_line(arg),
                        params=[param.get("name", "") for param in arg.get("params", []) if param.get("name")],
                        node=arg,
                        imports=dict(imports),
                        is_entrypoint=True,
                    )
                    self._register_function(func)
                elif atype == "Identifier":
                    qual = f"{module}.{arg.get('name')}" if module else arg.get("name")
                    if qual in self.functions:
                        self.functions[qual].is_entrypoint = True
                    else:
                        resolved = imports.get(arg.get("name", ""))
                        if resolved in self.functions:
                            self.functions[resolved].is_entrypoint = True
                elif atype == "MemberExpression":
                    target = self._js_member_name(arg, imports)
                    if target in self.functions:
                        self.functions[target].is_entrypoint = True

    # ------------------------------------------------------------------
    # JavaScript analysis
    # ------------------------------------------------------------------

    def _analyze_js_function(
        self,
        func: FunctionInfo,
        tainted: Set[str],
        call_stack: List[CallFrame],
    ) -> bool:
        body = (func.node.get("body") or {}).get("body") if isinstance(func.node.get("body"), dict) else func.node.get("body", [])
        if not isinstance(body, list):
            body = [func.node.get("body")] if func.node.get("body") else []
        return self._analyze_js_block(func, body, set(tainted), call_stack)

    def _analyze_js_block(
        self,
        func: FunctionInfo,
        statements: List[Dict[str, Any]],
        tainted: Set[str],
        call_stack: List[CallFrame],
    ) -> bool:
        return_tainted = False
        for stmt in statements or []:
            stype = (stmt or {}).get("type")
            if stype == "VariableDeclaration":
                for decl in stmt.get("declarations", []) or []:
                    ident = decl.get("id") or {}
                    init = decl.get("init")
                    expr_tainted = self._js_expr_tainted(func, init, tainted, call_stack)
                    if ident.get("type") == "Identifier":
                        name = ident.get("name")
                        if expr_tainted:
                            tainted.add(name)
                        else:
                            tainted.discard(name)
                continue

            if stype == "ExpressionStatement":
                expr = stmt.get("expression") or {}
                if expr.get("type") == "AssignmentExpression":
                    left = expr.get("left") or {}
                    right = expr.get("right")
                    expr_tainted = self._js_expr_tainted(func, right, tainted, call_stack)
                    if left.get("type") == "Identifier":
                        if expr_tainted:
                            tainted.add(left.get("name"))
                        else:
                            tainted.discard(left.get("name"))
                    else:
                        self._js_expr_tainted(func, expr, tainted, call_stack)
                else:
                    self._js_expr_tainted(func, expr, tainted, call_stack)
                continue

            if stype == "ReturnStatement":
                if self._js_expr_tainted(func, stmt.get("argument"), tainted, call_stack):
                    return_tainted = True
                continue

            if stype == "IfStatement":
                body_tainted = set(tainted)
                else_tainted = set(tainted)
                body_ret = self._analyze_js_block(
                    func,
                    (stmt.get("consequent") or {}).get("body", []) if (stmt.get("consequent") or {}).get("type") == "BlockStatement" else [stmt.get("consequent")] if stmt.get("consequent") else [],
                    body_tainted,
                    call_stack,
                )
                alternate = stmt.get("alternate")
                else_body = []
                if isinstance(alternate, dict):
                    else_body = alternate.get("body", []) if alternate.get("type") == "BlockStatement" else [alternate]
                else_ret = self._analyze_js_block(func, else_body, else_tainted, call_stack)
                tainted |= body_tainted | else_tainted
                return_tainted = return_tainted or body_ret or else_ret
                continue

            if stype in {"ForStatement", "ForOfStatement", "ForInStatement", "WhileStatement", "TryStatement"}:
                for key in ("body", "block", "finalizer"):
                    bucket = stmt.get(key)
                    if not bucket:
                        continue
                    nested = set(tainted)
                    body = bucket.get("body", []) if isinstance(bucket, dict) and bucket.get("type") == "BlockStatement" else [bucket]
                    return_tainted = return_tainted or self._analyze_js_block(func, body, nested, call_stack)
                    tainted |= nested
                for handler in stmt.get("handlers", []) or []:
                    nested = set(tainted)
                    body = (handler.get("body") or {}).get("body", [])
                    return_tainted = return_tainted or self._analyze_js_block(func, body, nested, call_stack)
                    tainted |= nested

        return return_tainted

    def _js_expr_tainted(
        self,
        func: FunctionInfo,
        node: Optional[Dict[str, Any]],
        tainted: Set[str],
        call_stack: List[CallFrame],
    ) -> bool:
        if not node:
            return False

        ntype = node.get("type")
        if self._is_js_source_expr(node):
            return True
        if ntype == "Identifier":
            return (node.get("name") or "") in tainted
        if ntype == "MemberExpression":
            return self._is_js_source_expr(node) or self._js_expr_tainted(func, node.get("object"), tainted, call_stack)
        if ntype == "Literal":
            return False
        if ntype in {"BinaryExpression", "LogicalExpression", "TemplateLiteral", "ArrayExpression", "ObjectExpression", "ConditionalExpression"}:
            return any(self._js_expr_tainted(func, child, tainted, call_stack) for child in self._js_child_nodes(node))
        if ntype == "CallExpression":
            return self._js_call_tainted(func, node, tainted, call_stack)
        if ntype == "AwaitExpression":
            return self._js_expr_tainted(func, node.get("argument"), tainted, call_stack)
        return any(self._js_expr_tainted(func, child, tainted, call_stack) for child in self._js_child_nodes(node))

    def _is_js_source_expr(self, node: Dict[str, Any]) -> bool:
        name = self._js_member_name(node)
        if name and any(source in name for source in REQUEST_SOURCE_HINTS):
            return True
        return False

    def _js_call_tainted(
        self,
        func: FunctionInfo,
        node: Dict[str, Any],
        tainted: Set[str],
        call_stack: List[CallFrame],
    ) -> bool:
        call_name = self._js_member_name(node.get("callee"), func.imports)
        if self._is_sanitizer(call_name):
            return False

        args = list(node.get("arguments", []) or [])
        arg_taints = [self._js_expr_tainted(func, arg, tainted, call_stack) for arg in args]

        sink = self._match_sink(call_name)
        if sink and any(arg_taints):
            self._record_finding(func, call_stack, call_name, self._js_line(node), sink)

        resolved = self._resolve_js_function(func, call_name)
        if resolved:
            callee_tainted = []
            for idx, param in enumerate(resolved.params):
                if idx < len(arg_taints) and arg_taints[idx]:
                    callee_tainted.append(param)
            if callee_tainted:
                frame = CallFrame(resolved.qualname, resolved.file, resolved.line, "call")
                nested_return = self._analyze_function(resolved, callee_tainted, call_stack + [frame])
                if nested_return:
                    return True

        if any(arg_taints):
            return True
        return False

    def _resolve_js_function(self, current_func: FunctionInfo, call_name: str) -> Optional[FunctionInfo]:
        if not call_name:
            return None
        if call_name in self.functions:
            return self.functions[call_name]
        if call_name in current_func.imports and current_func.imports[call_name] in self.functions:
            return self.functions[current_func.imports[call_name]]
        if "." not in call_name:
            direct = f"{current_func.module}.{call_name}" if current_func.module else call_name
            if direct in self.functions:
                return self.functions[direct]
        simple_matches = self._simple_index.get(("javascript", call_name.split(".")[-1]), [])
        if len(simple_matches) == 1:
            return self.functions.get(simple_matches[0])
        return None

    def _js_member_name(self, node: Optional[Dict[str, Any]], imports: Optional[Dict[str, str]] = None) -> str:
        if not node:
            return ""
        ntype = node.get("type")
        if ntype == "Identifier":
            name = node.get("name") or ""
            return (imports or {}).get(name, name)
        if ntype == "Literal":
            return str(node.get("value", ""))
        if ntype == "MemberExpression":
            obj = self._js_member_name(node.get("object"), imports)
            prop = self._js_member_name(node.get("property"), imports)
            if obj and prop:
                return f"{obj}.{prop}"
            return obj or prop
        if ntype == "CallExpression":
            return self._js_member_name(node.get("callee"), imports)
        return ""

    def _js_child_nodes(self, node: Dict[str, Any]) -> List[Dict[str, Any]]:
        children: List[Dict[str, Any]] = []
        for value in node.values():
            if isinstance(value, dict) and value.get("type"):
                children.append(value)
            elif isinstance(value, list):
                children.extend(item for item in value if isinstance(item, dict) and item.get("type"))
        return children

    def _js_line(self, node: Dict[str, Any]) -> int:
        return int((((node or {}).get("loc") or {}).get("start") or {}).get("line") or 1)

    def _walk_js_nodes(self, node: Any) -> Iterable[Dict[str, Any]]:
        if isinstance(node, dict):
            if node.get("type"):
                yield node
            for value in node.values():
                yield from self._walk_js_nodes(value)
        elif isinstance(node, list):
            for item in node:
                yield from self._walk_js_nodes(item)

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def _is_sanitizer(self, call_name: str) -> bool:
        lowered = str(call_name or "").lower()
        return any(hint.lower() in lowered for hint in SANITIZER_HINTS)

    def _match_sink(self, call_name: str) -> Optional[Tuple[str, str, str]]:
        lowered = str(call_name or "")
        for pattern, vuln_type, owasp, cwe in SINK_RULES:
            if pattern.search(lowered):
                return vuln_type, owasp, cwe
        return None

    def _record_finding(
        self,
        func: FunctionInfo,
        call_stack: List[CallFrame],
        sink_name: str,
        sink_line: int,
        sink_meta: Tuple[str, str, str],
    ) -> None:
        vuln_type, owasp, cwe = sink_meta
        trace = call_stack + [CallFrame(sink_name, func.file, sink_line, "sink")]
        evidence = "Taint flow:\n" + "\n".join(f"  - {frame.render()}" for frame in trace)
        self.findings.append(
            {
                "type": vuln_type,
                "title": f"Cross-file taint flow into {sink_name}",
                "category": "code",
                "file": func.file,
                "line": sink_line,
                "code": sink_name,
                "message": f"User-controlled input reaches {sink_name} across multiple files/functions.",
                "param": call_stack[0].symbol if call_stack else sink_name,
                "payload": "Tainted request input",
                "evidence": evidence,
                "confidence": 94,
                "severity": "High",
                "url": f"sast://{func.file}:{sink_line}",
                "owasp": owasp,
                "cwe": cwe,
                "language": func.language,
                "source": "taint-analyzer",
                "taint_path": [frame.render() for frame in trace],
            }
        )
