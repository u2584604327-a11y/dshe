#!/usr/bin/env python3
"""Signed v138 read-only DEX inventory. Direct calls != runtime isolation."""
import argparse, hashlib, re, zipfile
from pathlib import Path

SHA = "3ca56655d79afc57431636e340823e7071bc830615ca615c485b0b9a30b6e3e5"
BYTES = 147341486
DEX_NAME = re.compile(r"classes(?:[2-9][0-9]*)?\.dex\Z")
AI_BROWSER = "Lcom/dsh/android/browser/AiBrowserView;"
BRIDGE = "Lcom/dsh/android/browser/BrowserBridge;"
# Only EXACT DEX string-pool literals, not substrings of a message or asset.
MAILBOX_LITERALS = ("browser-cmd.json", "browser-result.json")

def exact_mailbox_literals(values):
    found = set(values)
    return {literal: (literal in found) for literal in MAILBOX_LITERALS}
API_CALLS = {
    "WEBVIEW_SUFFIX": "Landroid/webkit/WebView;->setDataDirectorySuffix(",
    "GLOBAL_CONFIG_SUFFIX": "Landroidx/webkit/ProcessGlobalConfig;->setDataDirectorySuffix(",
    "WEBVIEW_DISABLED": "Landroid/webkit/WebView;->disableWebView(",
    "COOKIE_INSTANCE": "Landroid/webkit/CookieManager;->getInstance(",
    "THIRD_PARTY_COOKIE": "Landroid/webkit/CookieManager;->setAcceptThirdPartyCookies(",
    "COOKIE_COPY": "Landroid/webkit/CookieManager;->setCookie(",
    "COOKIE_READ": "Landroid/webkit/CookieManager;->getCookie(",
    "COOKIE_DELETE_ALL": "Landroid/webkit/CookieManager;->removeAllCookies(",
}

def require(ok, code):
    if not ok:
        raise ValueError("B0_DENY_" + code)

def api_kind(output):
    text = "".join(output.split())
    for name, method in API_CALLS.items():
        if method in text:
            return name
    return None

def count_invocations(records):
    """Each record is (class_owner, opcode, API output); pure test helper."""
    totals = {key: 0 for key in API_CALLS}
    browser_cookies = 0
    for owner, opcode, output in records:
        if not opcode.startswith("invoke-"):
            continue
        name = api_kind(output)
        if not name:
            continue
        totals[name] += 1
        if owner.startswith("Lcom/dsh/android/browser/AiBrowserView") and (
                name.startswith("COOKIE_") or name == "THIRD_PARTY_COOKIE"):
            browser_cookies += 1
    return totals, browser_cookies

def analyze(path):
    file = Path(path)
    require(file.is_file(), "ORIGINAL_MISSING")
    require(file.stat().st_size == BYTES, "ORIGINAL_SIZE")
    digest = hashlib.sha256()
    with file.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1048576), b""):
            digest.update(chunk)
    require(digest.hexdigest() == SHA, "ORIGINAL_SHA")
    # Decode only after pinned original size/hash preflight has passed.
    from androguard.core.dex import DEX
    with zipfile.ZipFile(file) as archive:
        names = sorted([name for name in archive.namelist()
                        if DEX_NAME.fullmatch(name)],
                       key=lambda n: (n != "classes.dex", n))
        require(names and names[0] == "classes.dex" and
                len(names) <= 8 and len(names) == len(set(names)),
                "DEX_LAYOUT")
        dexes = []
        for name in names:
            require(0 < archive.getinfo(name).file_size < 65000000, "DEX_BOUNDS")
            dexes.append(DEX(archive.read(name)))
    classes = set()
    direct = []
    main_browser_ctor_count = 0
    # The signed binary may be different from upstream v91. Query only
    # bounded known string-pool keys, never dump all string literals.
    signed_mailbox = {key: False for key in MAILBOX_LITERALS}
    for dex in dexes:
        matched = exact_mailbox_literals(dex.get_strings())
        for key in MAILBOX_LITERALS:
            signed_mailbox[key] = signed_mailbox[key] or matched[key]
    inspected = 0
    for dex in dexes:
        for cls in dex.get_classes():
            owner = cls.get_name()
            classes.add(owner)
            for method in cls.get_methods():
                inspected += 1
                require(inspected <= 160000, "METHOD_BOUND")
                if method.get_code() is None:
                    continue
                for _pc, instruction in method.get_instructions_idx():
                    opcode = instruction.get_name()
                    if not opcode.startswith("invoke-"):
                        continue
                    output = instruction.get_output()
                    direct.append((owner, opcode, output))
                    require(len(direct) <= 1500000, "INVOKE_BOUND")
                    if (owner.startswith("Lcom/dsh/android/MainActivity") and
                            AI_BROWSER + "-><init>(" in "".join(output.split())):
                        main_browser_ctor_count += 1
    counts, browser_cookie_calls = count_invocations(direct)
    return {
        "dex_count": len(names),
        "ai_browser": AI_BROWSER in classes,
        "bridge": BRIDGE in classes,
        "main": "Lcom/dsh/android/MainActivity;" in classes,
        "app": "Lcom/dsh/android/DshApplication;" in classes,
        "browser_ctor": main_browser_ctor_count,
        "counts": counts,
        "browser_cookie_calls": browser_cookie_calls,
        "mailbox": signed_mailbox,
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("original_signed_v138")
    result = analyze(parser.parse_args().original_signed_v138)
    require(result["dex_count"] == 2 and result["main"] and result["app"],
            "PINNED_ORIGINAL_STRUCTURE")
    print("B0_SIGNED_V138_SHA256_AND_SIZE=PASS")
    print("B0_ORIGINAL_DEX_COUNT=" + str(result["dex_count"]))
    print("B0_ORIGINAL_AI_BROWSER_CLASS=" +
          ("PRESENT" if result["ai_browser"] else "NOT_FOUND"))
    print("B0_ORIGINAL_BROWSER_BRIDGE_CLASS=" +
          ("PRESENT" if result["bridge"] else "NOT_FOUND"))
    print("B0_MAIN_AI_BROWSER_DIRECT_CONSTRUCTOR_CALLS=" +
          str(result["browser_ctor"]))
    for key, amount in result["counts"].items():
        print("B0_DIRECT_" + key + "_CALLS=" + str(amount))
    print("B0_AI_BROWSER_COOKIE_API_CALLS=" + str(result["browser_cookie_calls"]))
    print("B0_SIGNED_DEX_SHARED_CMD_LITERAL=" +
          ("PRESENT" if result["mailbox"]["browser-cmd.json"] else "ABSENT"))
    print("B0_SIGNED_DEX_SHARED_RESULT_LITERAL=" +
          ("PRESENT" if result["mailbox"]["browser-result.json"] else "ABSENT"))
    print("B0_DEX_LITERAL_PRESENCE_IS_NOT_RUNTIME_MAILBOX_AUTHORIZATION=YES")
    print("B0_RUNTIME_WEBVIEW_PROFILE_STORAGE=NOT_ATTESTED")
    print("B0_CROSS_PROFILE_COOKIE_LOCALSTORAGE_ISOLATION=BLOCKED")
    print("B0_OS_WORK_PROFILE_UID_SEPARATION=NOT_ATTESTED")
    print("B0_AVF_PROTECTED_VM_GUEST=NOT_ATTESTED")
    print("B0_AI_BROWSER_PRODUCTION_FEATURES=DEFERRED")
    print("B0_APP_EXECUTED_OR_USER_DATA_READ=NO")

if __name__ == "__main__":
    main()
