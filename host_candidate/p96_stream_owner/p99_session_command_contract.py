#!/usr/bin/env python3
"""Safe static contract extraction for exact original SessionCommandController.
Prints identifiers/field/call shapes only; never original source text, user data,
credentials, prompts, or file contents.
"""
import argparse
import gzip
import io
import json
import pathlib
import re
import tarfile
import zipfile

from p96_original_engine_owner import SOURCE_BYTES, SOURCE_SHA, file_hash, require

TARGET = "node_modules/@deepseek-ai/dsh-api-session-controller/lib/index.js"
CLASS_NAME = "SessionCommandController"
MAX_MEMBER = 3_000_000

IDENT = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]{0,80}$")


def safe_ident(value):
    return bool(IDENT.fullmatch(value or ""))


def balanced_block(text, brace_index):
    require(0 <= brace_index < len(text) and text[brace_index] == "{", "P99_BAD_BRACE_START")
    depth = 0
    i = brace_index
    quote = None
    escape = False
    line_comment = False
    block_comment = False
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if line_comment:
            if ch == "\n":
                line_comment = False
            i += 1
            continue
        if block_comment:
            if ch == "*" and nxt == "/":
                block_comment = False
                i += 2
                continue
            i += 1
            continue
        if quote is not None:
            if escape:
                escape = False
                i += 1
                continue
            if ch == "\\":
                escape = True
                i += 1
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch == "/" and nxt == "/":
            line_comment = True
            i += 2
            continue
        if ch == "/" and nxt == "*":
            block_comment = True
            i += 2
            continue
        if ch in ("'", '"', "`"):
            quote = ch
            i += 1
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[brace_index + 1:i]
        i += 1
    raise RuntimeError("P99_UNBALANCED_BLOCK")


def balanced_parens(text, open_index):
    require(0 <= open_index < len(text) and text[open_index] == "(", "P99_BAD_PAREN_START")
    depth = 0
    i = open_index
    quote = None
    escape = False
    line_comment = False
    block_comment = False
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if line_comment:
            if ch == "\n":
                line_comment = False
            i += 1
            continue
        if block_comment:
            if ch == "*" and nxt == "/":
                block_comment = False
                i += 2
                continue
            i += 1
            continue
        if quote is not None:
            if escape:
                escape = False
                i += 1
                continue
            if ch == "\\":
                escape = True
                i += 1
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch == "/" and nxt == "/":
            line_comment = True
            i += 2
            continue
        if ch == "/" and nxt == "*":
            block_comment = True
            i += 2
            continue
        if ch in ("'", '"', "`"):
            quote = ch
            i += 1
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[open_index + 1:i]
        i += 1
    raise RuntimeError("P99_UNBALANCED_PARENS")


def method_contract(class_body, method_name):
    pat = re.compile(r"(?:(?:async|static)\s+)?" + re.escape(method_name) + r"\s*\(([^)]{0,500})\)\s*\{")
    match = pat.search(class_body)
    if not match:
        return None
    params = [x.strip() for x in match.group(1).split(",") if safe_ident(x.strip())][:16]
    brace = match.end() - 1
    body = balanced_block(class_body, brace)

    this_fields = sorted(set(re.findall(r"this\??\.([A-Za-z_$][A-Za-z0-9_$]{0,80})", body)))[:60]
    param_fields = {}
    for p in params:
        fields = sorted(set(re.findall(r"\b" + re.escape(p) + r"\??\.([A-Za-z_$][A-Za-z0-9_$]{0,80})", body)))
        if fields:
            param_fields[p] = fields[:60]

    member_calls = []
    for root, field, method in re.findall(
        r"\b(this|[A-Za-z_$][A-Za-z0-9_$]{0,80})\.([A-Za-z_$][A-Za-z0-9_$]{0,80})\.([A-Za-z_$][A-Za-z0-9_$]{0,80})\s*\(",
        body,
    ):
        item = f"{root}.{field}.{method}"
        if item not in member_calls:
            member_calls.append(item)
        if len(member_calls) >= 80:
            break

    direct_calls = []
    for name in re.findall(r"\b([A-Za-z_$][A-Za-z0-9_$]{0,80})\s*\(", body):
        if name not in {"if", "for", "while", "switch", "catch", "function"} and name not in direct_calls:
            direct_calls.append(name)
        if len(direct_calls) >= 80:
            break

    safe_literals = []
    for value in re.findall(r"['\"]([A-Za-z_$][A-Za-z0-9_$-]{0,48})['\"]", body):
        if safe_ident(value.replace("-", "_")) and value not in safe_literals:
            safe_literals.append(value)
        if len(safe_literals) >= 50:
            break

    assignments = []
    for field, rhs in re.findall(
        r"this\.([A-Za-z_$][A-Za-z0-9_$]{0,80})\s*=\s*([A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*){0,5})",
        body,
    ):
        item = {"field": field, "rhs": rhs}
        if item not in assignments:
            assignments.append(item)
        if len(assignments) >= 40:
            break

    call_assignments = []
    for field, chain, method, args in re.findall(
        r"this\.([A-Za-z_$][A-Za-z0-9_$]{0,80})\s*=\s*((?:[A-Za-z_$][A-Za-z0-9_$]{0,80}\.){1,5})([A-Za-z_$][A-Za-z0-9_$]{0,80})\s*\(([^)]{0,1000})\)",
        body,
    ):
        chain = chain.rstrip(".")
        ids = [
            x for x in re.findall(r"\b([A-Za-z_$][A-Za-z0-9_$]{0,80})\b", args)
            if safe_ident(x) and x not in {"true", "false", "null", "undefined", "await"}
        ]
        item = {
            "field": field,
            "callee": chain + "." + method,
            "argIdentifiers": list(dict.fromkeys(ids))[:40],
        }
        if item not in call_assignments:
            call_assignments.append(item)
        if len(call_assignments) >= 30:
            break

    param_use_counts = {
        p: len(re.findall(r"\b" + re.escape(p) + r"\b", body))
        for p in params
    }

    object_calls = []
    for root, method, args in re.findall(
        r"\b([A-Za-z_$][A-Za-z0-9_$]{0,80})\.([A-Za-z_$][A-Za-z0-9_$]{0,80})\s*\(([^)]{0,900})\)",
        body,
    ):
        if method not in {"steer", "followup", "commit", "resolveAgent", "createUserMessage", "bindPrompt", "admitPromptContent", "prompt"}:
            continue
        ids = [
            x for x in re.findall(r"\b([A-Za-z_$][A-Za-z0-9_$]{0,80})\b", args)
            if safe_ident(x) and x not in {"true", "false", "null", "undefined", "await"}
        ]
        fields = [
            f"{r}.{m}" for r, m in re.findall(
                r"\b([A-Za-z_$][A-Za-z0-9_$]{0,80})\??\.([A-Za-z_$][A-Za-z0-9_$]{0,80})",
                args,
            )
            if safe_ident(r) and safe_ident(m)
        ]
        item = {
            "root": root,
            "method": method,
            "argIdentifiers": list(dict.fromkeys(ids))[:40],
            "argFields": list(dict.fromkeys(fields))[:40],
        }
        if item not in object_calls:
            object_calls.append(item)
        if len(object_calls) >= 40:
            break

    mode_branches = []
    for op, value in re.findall(
        r"request\??\.mode\s*(===|==|!==|!=)\s*['\"]([A-Za-z_$][A-Za-z0-9_$-]{0,48})['\"]",
        body,
    ):
        item = {"operator": op, "value": value}
        if item not in mode_branches:
            mode_branches.append(item)

    direct_call_shapes = []
    target_calls = ("createUserMessage", "resolvePromptFileReceipts", "hasPromptRequest", "remoteErrorOf", "principalOf", "canonicalClientTimeZone", "hasPromptContent")
    call_pat = re.compile(r"\b(" + "|".join(map(re.escape, target_calls)) + r")\s*\(")
    for match in call_pat.finditer(body):
        method = match.group(1)
        open_index = body.find("(", match.start(), match.end())
        if open_index < 0:
            continue
        try:
            args = balanced_parens(body, open_index)
        except Exception:
            continue
        ids = [
            x for x in re.findall(r"\b([A-Za-z_$][A-Za-z0-9_$]{0,80})\b", args)
            if safe_ident(x) and x not in {"true", "false", "null", "undefined", "await"}
        ]
        fields = [
            f"{r}.{m}" for r, m in re.findall(
                r"\b([A-Za-z_$][A-Za-z0-9_$]{0,80})\??\.([A-Za-z_$][A-Za-z0-9_$]{0,80})",
                args,
            )
            if safe_ident(r) and safe_ident(m)
        ]
        item = {
            "method": method,
            "argIdentifiers": list(dict.fromkeys(ids))[:60],
            "argFields": list(dict.fromkeys(fields))[:60],
        }
        if item not in direct_call_shapes:
            direct_call_shapes.append(item)
        if len(direct_call_shapes) >= 30:
            break

    return {
        "name": method_name,
        "params": params,
        "thisFields": this_fields,
        "paramFields": param_fields,
        "memberCalls": member_calls,
        "directCalls": direct_calls,
        "objectCalls": object_calls,
        "modeBranches": mode_branches,
        "directCallShapes": direct_call_shapes,
        "safeLiterals": safe_literals,
        "assignments": assignments,
        "callAssignments": call_assignments,
        "paramUseCounts": param_use_counts,
        "sourceSize": len(body),
    }


def find_class_body(source, class_name, required_method):
    occurrences = list(re.finditer(r"\b" + re.escape(class_name) + r"\b", source))
    require(bool(occurrences), "P99_CLASS_TOKEN_NOT_FOUND_" + class_name)
    for match in occurrences:
        search_end = min(len(source), match.end() + 800)
        brace = source.find("{", match.end(), search_end)
        if brace < 0:
            continue
        try:
            candidate = balanced_block(source, brace)
        except Exception:
            continue
        if method_contract(candidate, required_method) is not None:
            return candidate, len(occurrences)
    raise RuntimeError("P99_CLASS_BODY_NOT_FOUND_" + class_name)


def extract_source(apk):
    require(apk.stat().st_size == SOURCE_BYTES, "APK_SIZE_DRIFT")
    require(file_hash(apk) == SOURCE_SHA, "APK_SHA_DRIFT")
    with zipfile.ZipFile(apk) as zf:
        require(zf.testzip() is None, "APK_CRC")
        engine = zf.read("assets/engine.bin")
    with tarfile.open(fileobj=gzip.GzipFile(fileobj=io.BytesIO(engine)), mode="r|") as tf:
        for item in tf:
            if item.name != TARGET:
                continue
            require(item.isfile(), "TARGET_NOT_FILE")
            require(0 <= item.size <= MAX_MEMBER, "TARGET_TOO_LARGE")
            fh = tf.extractfile(item)
            require(fh is not None, "TARGET_MISSING")
            raw = fh.read(MAX_MEMBER + 1)
            require(len(raw) == item.size, "TARGET_SHORT_READ")
            return raw.decode("utf-8")
    raise RuntimeError("P99_TARGET_NOT_FOUND")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--original", required=True)
    args = parser.parse_args()
    source = extract_source(pathlib.Path(args.original))

    imports = []
    for names, spec in re.findall(
        r"import\s*\{([^}]{1,1200})\}\s*from\s*['\"](@deepseek-ai/[^'\"]{1,120})['\"]",
        source,
    ):
        imported = []
        for raw in names.split(","):
            part = raw.strip()
            if not part:
                continue
            local = part.split(" as ")[-1].strip()
            original = part.split(" as ")[0].strip()
            if safe_ident(local) and safe_ident(original):
                imported.append({"imported": original, "local": local})
        if imported:
            imports.append({"package": spec, "names": imported[:30]})
        if len(imports) >= 60:
            break
    print("P99_SESSION_CONTROLLER_IMPORTS=" + json.dumps(imports, sort_keys=True))

    controller_body, controller_occurrences = find_class_body(source, "SessionController", "prompt")
    controller_prompt = method_contract(controller_body, "prompt")

    class_body, occurrences = find_class_body(source, CLASS_NAME, "prompt")

    constructor = method_contract(class_body, "constructor")
    prompt = method_contract(class_body, "prompt")
    resolve_agent = method_contract(class_body, "resolveAgent")
    require(prompt is not None, "P99_PROMPT_NOT_FOUND")
    require(resolve_agent is not None, "P99_RESOLVE_AGENT_NOT_FOUND")

    agent_body, agent_occurrences = find_class_body(source, "ApiSessionAgentController", "resolveAgent")
    agent_constructor = method_contract(agent_body, "constructor")
    agent_resolve = method_contract(agent_body, "resolveAgent")
    agent_selection = method_contract(agent_body, "selectionFor")
    agent_serialize = method_contract(agent_body, "serializeImageAdmission")
    resolve_bindings = []
    for rhs in re.findall(
        r"\bresolve\s*=\s*((?:this\.)?[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*){0,6})",
        agent_body,
    ):
        if rhs not in resolve_bindings:
            resolve_bindings.append(rhs)
        if len(resolve_bindings) >= 12:
            break

    print("P99_SESSION_CONTROLLER_CLASS_TOKEN_OCCURRENCES=" + str(controller_occurrences))
    print("P99_SESSION_CONTROLLER_PROMPT_FULL=" + json.dumps(controller_prompt, sort_keys=True))
    print("P99_SESSION_COMMAND_CLASS_TOKEN_OCCURRENCES=" + str(occurrences))
    print("P99_SESSION_COMMAND_CLASS_FOUND=PASS")
    print("P99_SESSION_COMMAND_CONSTRUCTOR=" + json.dumps(constructor, sort_keys=True))
    print("P99_SESSION_COMMAND_PROMPT=" + json.dumps(prompt, sort_keys=True))
    print("P99_SESSION_COMMAND_RESOLVE_AGENT=" + json.dumps(resolve_agent, sort_keys=True))
    print("P99_AGENT_CONTROLLER_CLASS_TOKEN_OCCURRENCES=" + str(agent_occurrences))
    print("P99_AGENT_CONTROLLER_CONSTRUCTOR=" + json.dumps(agent_constructor, sort_keys=True))
    print("P99_AGENT_CONTROLLER_RESOLVE_AGENT=" + json.dumps(agent_resolve, sort_keys=True))
    print("P99_AGENT_CONTROLLER_RESOLVE_BINDINGS=" + json.dumps(resolve_bindings, sort_keys=True))
    print("P99_AGENT_CONTROLLER_SELECTION_FOR=" + json.dumps(agent_selection, sort_keys=True))
    print("P99_AGENT_CONTROLLER_SERIALIZE_IMAGE=" + json.dumps(agent_serialize, sort_keys=True))
    print("P99_SESSION_COMMAND_SOURCE_EXPORTED=NO")
    print("P99_SESSION_COMMAND_RUNTIME_EXECUTED=NO")


if __name__ == "__main__":
    main()
