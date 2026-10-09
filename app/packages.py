import hashlib
import re
from pathlib import PurePosixPath

import yaml

# Intentionally narrow execution contract. A Compose document is executable code;
# publishing it does not grant permission to run it.
ALLOWED_SERVICE = {
    "image",
    "command",
    "entrypoint",
    "environment",
    "working_dir",
    "volumes",
    "network_mode",
    "read_only",
    "tmpfs",
    "user",
    "cap_drop",
    "security_opt",
    "mem_limit",
    "cpus",
    "pids_limit",
}
ALLOWED_ENV = {"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"}


def validate_compose(source, report_path="report.json"):
    if len(source.encode()) > 65536:
        raise ValueError("Compose file exceeds 64 KiB")
    try:
        value = yaml.safe_load(source)
    except yaml.YAMLError as error:
        raise ValueError("Invalid Compose YAML") from error
    if not isinstance(value, dict) or set(value) != {"services"}:
        raise ValueError("Scanner packages must contain only services")
    services = value["services"]
    if not isinstance(services, dict) or len(services) != 1 or "scanner" not in services:
        raise ValueError("Define exactly one service named scanner")
    service = services["scanner"]
    if not isinstance(service, dict) or set(service) - ALLOWED_SERVICE:
        raise ValueError("Unsupported or unsafe Compose service field")
    image = service.get("image", "")
    if (
        not isinstance(image, str)
        or not re.fullmatch(r"[A-Za-z0-9._/:-]+(?:@sha256:[a-f0-9]{64})?", image)
        or (":" not in image.split("/")[-1] and "@sha256:" not in image)
    ):
        raise ValueError("Use an explicit image version or digest without interpolation")
    for mount in service.get("volumes", []):
        if mount not in ("${SOURCE_DIR}:/src:ro", "${REPORT_DIR}:/reports:rw"):
            raise ValueError("Mount only SOURCE_DIR read-only or REPORT_DIR read-write")
    environment = service.get("environment", {})
    if not isinstance(environment, dict) or set(environment) - ALLOWED_ENV:
        raise ValueError("Only proxy environment variables are allowed")
    for key, val in environment.items():
        if val != "${" + key + "}":
            raise ValueError("Proxy settings must use runtime placeholders")
    if service.get("network_mode", "none") != "none":
        raise ValueError("Scanner networking must be disabled; use a reviewed integration for online tools")
    if service.get("read_only", True) is not True or service.get("cap_drop", ["ALL"]) != ["ALL"]:
        raise ValueError("Read-only root and ALL capability drop required")
    if service.get("security_opt", ["no-new-privileges:true"]) != ["no-new-privileges:true"]:
        raise ValueError("No-new-privileges is required")
    tmpfs = service.get("tmpfs", ["/tmp:size=256m"])
    if tmpfs != ["/tmp:size=256m"]:
        raise ValueError("Use the bounded /tmp scratch mount")
    user = str(service.get("user", "65532:65532"))
    if not re.fullmatch(r"[1-9][0-9]{0,5}(?::[1-9][0-9]{0,5})?", user):
        raise ValueError("Use a non-root numeric container user")
    path = PurePosixPath(report_path)
    if path.is_absolute() or ".." in path.parts or not re.fullmatch(r"[A-Za-z0-9_./-]+", report_path):
        raise ValueError("Report path must stay inside /reports")
    for field in ("command", "entrypoint"):
        val = service.get(field)
        if val is not None and not isinstance(val, (str, list)):
            raise ValueError("Commands must be strings or arrays")
        if isinstance(val, list) and not all(isinstance(x, str) for x in val):
            raise ValueError("Command arguments must be strings")
    if service.get("working_dir", "/src") not in ("/src", "/reports", "/tmp"):
        raise ValueError("Unsupported working directory")
    # Limits are imposed by the runner, rather than trusted from this document.
    return value, hashlib.sha256(source.encode()).hexdigest()


def runtime_compose(source, registry="", cpus="1.0", memory="512m"):
    value, _ = validate_compose(source)
    service = value["services"]["scanner"]
    if registry:
        if not re.fullmatch(r"[A-Za-z0-9.:-]+(?:/[A-Za-z0-9._/-]+)?", registry):
            raise ValueError("Registry prefix invalid")
        image = service["image"]
        service["image"] = registry.rstrip("/") + "/" + image
    service.update(
        network_mode="none",
        read_only=True,
        cap_drop=["ALL"],
        security_opt=["no-new-privileges:true"],
        mem_limit=memory,
        cpus=cpus,
        pids_limit=128,
        tmpfs=["/tmp:size=256m"],
    )
    service.setdefault("user", "65532:65532")
    return yaml.safe_dump(value, sort_keys=False)
