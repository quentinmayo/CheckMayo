import os
import resource
import sys

resource.setrlimit(resource.RLIMIT_CPU, (5, 5))
resource.setrlimit(resource.RLIMIT_FSIZE, (1_000_000, 1_000_000))
resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
# OPA's Go runtime reserves address space; CPU/file limits and the container's
# memory limit are used instead of a restrictive RLIMIT_AS.
os.execv(sys.argv[1], sys.argv[1:])
