#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Tên cũ của checks/asal.py, giữ lại để lệnh cũ vẫn chạy.

  asal_check.py config  ->  asal.py collect
  asal_check.py probe   ->  asal.py probe
  asal_check.py         ->  asal.py collect, rồi asal.py probe

Dùng thẳng checks/asal.py cho việc mới.
"""
import os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import asal  # noqa: E402

PROBE_ONLY_WITH_VALUE = {"--probe-host", "--ipv4", "--ipv6", "--dns", "--keychain-item", "--host-home"}
PROBE_ONLY_FLAGS = {"--no-network"}


def collect_args(rest):
    out, skip = [], False
    for a in rest:
        if skip:
            skip = False
            continue
        name = a.split("=", 1)[0]
        if name in PROBE_ONLY_WITH_VALUE:
            skip = "=" not in a
            continue
        if name in PROBE_ONLY_FLAGS:
            continue
        out.append(a)
    return out


def main(argv):
    print("asal_check.py đã đổi tên thành asal.py; lệnh này vẫn chạy nhưng sẽ bị bỏ ở bản sau.", file=sys.stderr)
    mode = argv[0] if argv and argv[0] in ("all", "config", "probe") else "all"
    rest = argv[1:] if argv and argv[0] in ("all", "config", "probe") else argv
    if mode == "config":
        return asal.main(["collect"] + collect_args(rest))
    if mode == "probe":
        return asal.main(["probe"] + rest)
    a = asal.main(["collect"] + collect_args(rest))
    b = asal.main(["probe"] + rest)
    return max(a, b)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
