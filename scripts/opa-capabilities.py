import json
import subprocess
from pathlib import Path

capabilities = json.loads(subprocess.check_output(["opa", "capabilities", "--current"]))
# Policies have no network, environment, or wall-clock side effects.
capabilities["builtins"] = [
    b
    for b in capabilities["builtins"]
    if b["name"] not in ("http.send", "net.lookup_ip_addr", "opa.runtime", "time.now_ns")
]
capabilities["allow_net"] = []
Path("app/opa-capabilities.json").write_text(json.dumps(capabilities))
