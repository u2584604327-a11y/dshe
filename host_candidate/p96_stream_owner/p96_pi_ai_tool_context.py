#!/usr/bin/env python3
"""Print bounded first-party-independent tool serialization source facts.
Only ephemeral, SHA-pinned original pi-ai module path, never account data.
"""
from pathlib import Path
import re
root=Path(__file__).resolve().parent / ".unused"
import sys
assert len(sys.argv)==2
base=Path(sys.argv[1])
assert base.name=="runtime"
folder=base/"node_modules"/"@earendil-works"/"pi-ai"
assert folder.is_dir()
paths=sorted(p for p in folder.rglob("*openai-completions*")
             if p.suffix in (".js",".cjs",".mjs") and p.is_file())
print("P96_PI_AI_OPENAI_CODE_FILES="+str(len(paths)))
for p in paths[:12]:
    b=p.read_bytes()
    if len(b)>2000000:continue
    print("P96_ORIGINAL_PI_AI_TOOL_CODE_FILE="+p.relative_to(folder).as_posix())
    for pattern in (b"transcriptTools",b"requestTools",b"collectTranscript",
                    b"toolsAdded",b"toolsRemoved",b"context.tools",
                    b"options.tools",b"params.tools",b"toolChoice"):
        for m in list(re.finditer(re.escape(pattern),b))[:2]:
            start=max(0,m.start()-180);end=min(len(b),m.end()+250)
            text=b[start:end].decode("utf-8","replace")
            text=re.sub(r"[\x00-\x1f\x7f]"," ",text)
            text=re.sub(r"(?:Bearer |sk-)[a-zA-Z0-9._-]{8,}","<CREDENTIAL>",text)
            print("P96_TOOL_CODE_ANCHOR="+pattern.decode()+
                  " @"+str(m.start())+" | "+text[:430])
