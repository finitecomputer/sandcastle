#!/usr/bin/env python3
"""Line 9's cold-read study (docs/nitro-spike.md, "Where the cold 9 s
go"), run on the parent as its build user:

  ./cold-reads.py chat <name> <samples> [--mode direct] [--root linear]
                  [--setting readahead|verity-prefetch|working-set]
  ./cold-reads.py gateway <name> <samples> [the same]
                  [--image hermes-pyc]   # another image of ~/nitro/images
  ./cold-reads.py record chat|gateway   # the working set, once
  ./cold-reads.py trace <name>          # every read, once, by strace

Each sample is one fresh computer on line 8's plain disk (no key: the
study is the root's reads, not the seal): a cold `hermes chat` and then
a warm one, or Hermes' gateway booted and one message through its API
server. The guest's block devices' counters are read around the cold
start. Results append to ~/cold/results.jsonl as one JSON object a
sample. A measurement's harness, not a computer's: the workload starts
from cold-entry.sh beside it (no NSM clock, so direct mode boots too), and a
setting is a sysfs write or a parallel read of a recorded file list.

Python, not Rust: it drives the spike's own binary and parses its
output, as parent-ready.sh does for the host.
"""
import json
import os
import subprocess
import sys
import threading
import time

HOME = os.path.expanduser("~")
BIN = f"{HOME}/sandcastle/target/release/sandcastle-nitro-spike"
HELD = "/run/nitro-spike/held"
COLD = f"{HOME}/cold"
# The workload's first script, beside this one.
ENTRY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cold-entry.sh")
LOG = f"{COLD}/hold.log"
REPLY = "NITRO-SPIKE-STAND-IN-MODEL"
ENV = json.load(open(f"{HOME}/hermes-config.json"))["Env"] + ["OPENAI_API_KEY=sk-stand-in"]
DEVICES = ["vda", "vdb", "vdc", "dm-0", "loop0"]
WAIT_S = 120


def env_flags():
    return [x for e in ENV for x in ("--env", e)]


def run(cmd, timeout, stdin_file=None):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if r.returncode != 0:
        raise RuntimeError(f"{cmd[2] if len(cmd) > 2 else cmd}: {r.stdout[-400:]} {r.stderr[-400:]}")
    return r.stdout


def exec_sh(script, timeout=300, stdin_file=None):
    cmd = ["sudo", BIN, "exec", "--dir", HELD] + env_flags() + (["--stdin", stdin_file] if stdin_file else []) + ["--", "/bin/sh", "-c", script]
    return json.loads(run(cmd, timeout))


def kill_all():
    for name in ["sandcastle-nitr", "firecracker", "fpac-bench"]:
        subprocess.run(["sudo", "pkill", "-x", name])
    for _ in range(100):
        if subprocess.run(["pgrep", "-x", "firecracker"], capture_output=True).returncode != 0:
            return
        time.sleep(0.1)
    raise RuntimeError("a Firecracker outlived its kill")


def wait_for(text, t0):
    deadline = time.time() + WAIT_S
    while time.time() < deadline:
        try:
            if text in open(LOG).read():
                return round((time.time() - t0) * 1000)
        except FileNotFoundError:
            pass
        time.sleep(0.01)
    raise RuntimeError(f"no {text!r} in {WAIT_S} s: {open(LOG).read()[-600:]}")


def stat_script():
    return "for d in " + " ".join(DEVICES) + "; do [ -e /sys/block/$d/stat ] && echo \"stat $d $(cat /sys/block/$d/stat)\"; done"


def parse_stats(out):
    s = {}
    for line in out.splitlines():
        p = line.split()
        if len(p) > 6 and p[0] == "stat":
            # /sys/block/<d>/stat: reads, merged, sectors, read ms, ...
            s[p[1]] = {"reads": int(p[2]), "merged": int(p[3]), "bytes": int(p[4]) * 512, "read_ms": int(p[5])}
    return s


def delta(a, b):
    return {d: {k: b[d][k] - a[d][k] for k in b[d]} for d in b if d in a}


# The workload's /sys is read-only (as in a container); a sysfs of its
# own, mounted aside, takes the writes for the whole guest.
SYSFS = "mkdir -p /tmp/sys2; grep -q ' /tmp/sys2 ' /proc/mounts || mount -t sysfs sysfs /tmp/sys2; "
SETTINGS = {
    # Readahead 4 MiB on the root's devices (the default is 128 KiB).
    "readahead": SYSFS + "for d in dm-0 vdb vda; do echo 4096 > /tmp/sys2/block/$d/queue/read_ahead_kb; done; cat /sys/block/dm-0/queue/read_ahead_kb",
    # dm-verity's hash prefetch, 256 KiB by default, to 4 MiB.
    "verity-prefetch": SYSFS + "echo 4194304 > /tmp/sys2/module/dm_verity/parameters/prefetch_cluster; cat /sys/module/dm_verity/parameters/prefetch_cluster",
}
DEFAULTS = "echo ra $(cat /sys/block/dm-0/queue/read_ahead_kb) $(cat /sys/block/vdb/queue/read_ahead_kb); echo prefetch $(cat /sys/module/dm_verity/parameters/prefetch_cluster 2>/dev/null || echo none); grep -o 'dm-mod.create=\"[^,]*,,,ro,0 [0-9]* [a-z]*' /proc/cmdline | awk '{print \"table\", $NF}'"

# The recorded working set read in one pass, 16 readers at once.
PREFETCH = "s=$(date +%s%N); xargs -d '\\n' -P 16 -n 32 cat > /dev/null 2>&1; e=$(date +%s%N); echo prefetch_ms $(( (e - s) / 1000000 ))"


def hold(args, gateway):
    cmd = ["sudo", BIN, "hold", "--kernel", f"{HOME}/nitro/guest-kernel/out/Image", "--initrd", f"{HOME}/nitro/images/guest.initrd",
           "--image-json", f"{HOME}/nitro/images/{args[args.index('--image') + 1] if '--image' in args else 'hermes'}.json", "--image-config", f"{HOME}/hermes-config.json",
           "--kms-key", open(f"{COLD}/kms-key").read().strip(), "--mem-mib", "4096", "--scratch-gib", "24",
           "--store", f"{HOME}/nitro/store-plain-1gb", "--disk", "hermes", "--fpac-bench", f"{HOME}/fpac/target/release/fpac-bench",
           "--volume-gb", "40", "--object-ms", "23", "--put-bytes-per-s", "90000000",
           "--entrypoint-file", ENTRY, "--env", f"NITRO_NOW={int(time.time())}", "--env", "NITRO_PLAIN=1"]
    for f in ("--mode", "--root"):
        if f in args:
            cmd += [f, args[args.index(f) + 1]]
    if gateway:
        cmd += ["--hermes-gateway", "true", "--env", "API_SERVER_ENABLED=true"]
    return subprocess.Popen(cmd, stdout=open(LOG, "w"), stderr=subprocess.STDOUT)


def stop_hermes(kind):
    """Hermes stopped as a platform stops a container, so the next life
    finds no unclean exit: s6-overlay's own halt for the gateway (its
    services stopped in order, then SIGTERM to the rest, FPAC included),
    SIGTERM to Hermes' processes for the chat runs. The time it took."""
    t = time.time()
    if kind == "gateway":
        try:
            exec_sh("/run/s6/basedir/bin/halt", timeout=60)
        except Exception:
            pass  # the guest may go down before the exec answers
        for _ in range(600):
            if subprocess.run(["pgrep", "-x", "firecracker"], capture_output=True).returncode != 0:
                break
            time.sleep(0.05)
    else:
        exec_sh("ps -eo pid,args | awk '/hermes_cli\\.main|hermes chat/ && !/awk/ {print $1}' | xargs -r kill -TERM; i=0; while ps -eo args | grep -q '[h]ermes_cli.main' && [ $i -lt 300 ]; do sleep 0.1; i=$((i+1)); done; echo $i", timeout=60)
    return round((time.time() - t) * 1000)


def sleep_disk():
    # FPAC's sleep, so the next life opens a clean head (as lives does).
    exec_sh("kill -TERM $(cat /proc/[0-9]*/stat 2>/dev/null | awk '$2==\"(fpac)\" {print $1}'); i=0; while pidof fpac > /dev/null && [ $i -lt 600 ]; do sleep 0.1; i=$((i+1)); done", timeout=120)


GATEWAY_MESSAGE = (
    "until [ -f /opt/data/.env ] && k=$(grep '^API_SERVER_KEY=' /opt/data/.env | cut -d= -f2-) && [ -n \"$k\" ] && "
    "curl -sf -m 60 -o /tmp/reply.json -H \"Authorization: Bearer $k\" -H 'Content-Type: application/json' "
    "-d '{\"model\":\"hermes-agent\",\"messages\":[{\"role\":\"user\",\"content\":\"Say hello.\"}]}' http://127.0.0.1:8642/v1/chat/completions; "
    "do sleep 0.05; done; grep -c " + REPLY + " /tmp/reply.json"
)


def sample(kind, name, args, index, trace=False):
    setting = args[args.index("--setting") + 1] if "--setting" in args else None
    kill_all()
    t0 = time.time()
    p = hold(args, kind == "gateway")
    row = {"name": name, "kind": kind, "sample": index, "setting": setting, "image": args[args.index("--image") + 1] if "--image" in args else "hermes", "mode": args[args.index("--mode") + 1] if "--mode" in args else "confidential", "root": args[args.index("--root") + 1] if "--root" in args else "verity"}
    row["time_line_ms"] = wait_for("nitro: time", t0)
    row["defaults"] = exec_sh(DEFAULTS)["stdout"].split("\n")
    if setting in SETTINGS:
        row["setting_out"] = exec_sh(SETTINGS[setting])["stdout"].strip()
    prefetch = {}
    if setting == "working-set":
        def go():
            prefetch["out"] = exec_sh(PREFETCH, timeout=300, stdin_file=f"{COLD}/working-set-{kind}.txt")["stdout"].strip()
            prefetch["done_ms"] = round((time.time() - t0) * 1000)
        th = threading.Thread(target=go)
        th.start()
    if kind == "gateway":
        before = parse_stats(exec_sh(stat_script())["stdout"])
        # Hermes starts after the mount; the message is sent from then on.
        row["mounted_ms"] = wait_for("nitro: mounted", t0)
        # The PID the last life left in Hermes' home (on the persistent
        # disk), read before Hermes starts: a fresh VM reuses PIDs.
        row["pid_file_at_mount"] = exec_sh("cat /opt/data/gateway.pid 2>/dev/null | head -c 300 || echo none")["stdout"].strip()
        r = exec_sh(GATEWAY_MESSAGE, timeout=300)
        row["reply_at_ms"] = round((time.time() - t0) * 1000)
        row["replied"] = r["stdout"].strip() not in ("", "0")
        row["reads"] = delta(before, parse_stats(exec_sh(stat_script())["stdout"]))
        # Hermes' own logs, with their timestamps, for where its start goes.
        row["replaced"] = exec_sh("grep -h 'Replacing existing gateway\\|did not exit after SIGTERM' /opt/data/logs/gateway.log /opt/data/logs/gateways/default/current 2>/dev/null | tail -3")["stdout"].strip()
        logs = exec_sh("for f in /opt/data/logs/gateways/default/current /opt/data/logs/gateway.log /opt/data/logs/agent.log; do echo \"== $f\"; tail -n 120 $f 2>&1; done; echo \"== clock $(date +%s.%N)\"", timeout=60)["stdout"]
        with open(f"{COLD}/gw-logs-{name}-{index}.txt", "w") as f:
            f.write(f"launched_at {t0:.3f}\nreplied_at {t0 + row['reply_at_ms'] / 1000:.3f}\n" + open(LOG).read() + "\n" + logs)
    else:
        row["mounted_ms"] = wait_for("nitro: mounted", t0)
        tracer = None
        if trace:
            pid = run(["pgrep", "-x", "firecracker"], 10).split()[0]
            fds = run(["sudo", "ls", "-l", f"/proc/{pid}/fd"], 10)
            row["trace_fds"] = [l.split()[-3] + " " + l.split()[-1] for l in fds.splitlines() if "hermes." in l]
            # Firecracker's block device reads its file by lseek and read.
            tracer = subprocess.Popen(["sudo", "strace", "-f", "-qq", "-s", "0", "-e", "trace=lseek,read,readv,pread64,preadv", "-p", pid, "-o", f"{COLD}/trace-{name}.txt"])
            time.sleep(1)
        chat = f"{stat_script()}; echo cpu0 $(head -1 /proc/stat); cd /opt/data; s=$(date +%s%N); hermes chat -Q -q 'Say hello.' > /tmp/chat.out 2>&1; c=$?; e=$(date +%s%N); echo ms $(( (e - s) / 1000000 )); echo code $c; grep -c {REPLY} /tmp/chat.out | sed 's/^/replied /'; echo cpu1 $(head -1 /proc/stat); {stat_script()}"
        out = exec_sh(chat, timeout=300)["stdout"]
        row["cold_reply_at_ms"] = round((time.time() - t0) * 1000)
        if tracer:
            subprocess.run(["sudo", "pkill", "-INT", "-x", "strace"])
            tracer.wait(timeout=30)
        lines = out.splitlines()
        half = [i for i, l in enumerate(lines) if l.startswith("ms ")][0]
        row["cold_ms"] = int(lines[half].split()[1])
        row["cold_code"] = int(lines[half + 1].split()[1])
        row["cold_replied"] = int(lines[half + 2].split()[1]) > 0
        row["reads"] = delta(parse_stats("\n".join(lines[:half])), parse_stats("\n".join(lines[half:])))
        cpu = {l.split()[0]: [int(x) for x in l.split()[2:5]] for l in lines if l.startswith("cpu0 ") or l.startswith("cpu1 ")}
        row["cold_cpu_s"] = round(sum(cpu["cpu1"]) / 100 - sum(cpu["cpu0"]) / 100, 2)
        warm = exec_sh("cd /opt/data; s=$(date +%s%N); hermes chat -Q -q 'Say hello.' > /tmp/chat2.out 2>&1; e=$(date +%s%N); echo $(( (e - s) / 1000000 )); grep -c " + REPLY + " /tmp/chat2.out", timeout=300)["stdout"].split()
        row["warm_ms"] = int(warm[0])
        row["warm_replied"] = int(warm[1]) > 0
        # The same again with the guest's page cache dropped: what a cold
        # read of every file costs, with Hermes' first-run work done.
        dropped = exec_sh(f"sync; echo 3 > /proc/sys/vm/drop_caches; {stat_script()}; cd /opt/data; s=$(date +%s%N); hermes chat -Q -q 'Say hello.' > /tmp/chat3.out 2>&1; e=$(date +%s%N); echo ms $(( (e - s) / 1000000 )); grep -c {REPLY} /tmp/chat3.out | sed 's/^/replied /'; {stat_script()}", timeout=300)["stdout"].splitlines()
        at = [i for i, l in enumerate(dropped) if l.startswith("ms ")][0]
        row["dropped_ms"] = int(dropped[at].split()[1])
        row["dropped_replied"] = int(dropped[at + 1].split()[1]) > 0
        row["dropped_reads"] = delta(parse_stats("\n".join(dropped[:at])), parse_stats("\n".join(dropped[at:])))
    if setting == "working-set":
        th.join(timeout=300)
        row["prefetch"] = prefetch
    row["stop_ms"] = stop_hermes(kind)
    if kind != "gateway":
        sleep_disk()
    kill_all()
    p.wait(timeout=30)
    with open(f"{COLD}/results.jsonl", "a") as f:
        f.write(json.dumps(row) + "\n")
    print(json.dumps({k: row[k] for k in row if k not in ("defaults", "reads")}), flush=True)
    return row


# The working set: every regular file of the root with pages in the
# guest's page cache after a cold start, by mincore (the image has no
# fincore), largest first. Run in the guest by the image's python3.
RECORD = r'''
import ctypes, os, stat
libc = ctypes.CDLL(None, use_errno=True)
libc.mmap.restype = ctypes.c_void_p
libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
libc.mincore.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
PAGE = os.sysconf("SC_PAGE_SIZE")
root = os.stat("/").st_dev
skip = {"/proc", "/sys", "/dev", "/run", "/tmp", "/opt/data", "/var/lib/fpac"}
found = []
for dp, dns, fns in os.walk("/"):
    dns[:] = [d for d in dns if os.path.join(dp, d) not in skip and os.lstat(os.path.join(dp, d)).st_dev == root]
    for f in fns:
        p = os.path.join(dp, f)
        try:
            st = os.lstat(p)
            if not stat.S_ISREG(st.st_mode) or st.st_size == 0:
                continue
            fd = os.open(p, os.O_RDONLY)
        except OSError:
            continue
        try:
            a = libc.mmap(None, st.st_size, 1, 1, fd, 0)
            if a in (None, ctypes.c_void_p(-1).value):
                continue
            n = (st.st_size + PAGE - 1) // PAGE
            vec = (ctypes.c_ubyte * n)()
            if libc.mincore(a, st.st_size, vec) == 0:
                c = sum(v & 1 for v in vec)
                if c:
                    found.append((c * PAGE, st.st_size, p))
            libc.munmap(a, st.st_size)
        finally:
            os.close(fd)
found.sort(reverse=True)
print("files", len(found), "cached_bytes", sum(x[0] for x in found), "file_bytes", sum(x[1] for x in found))
for c, size, p in found:
    print(c, size, p)
'''


def record(kind):
    kill_all()
    t0 = time.time()
    p = hold([], kind == "gateway")
    wait_for("nitro: mounted", t0)
    if kind == "gateway":
        exec_sh(GATEWAY_MESSAGE, timeout=300)
    else:
        exec_sh(f"cd /opt/data; hermes chat -Q -q 'Say hello.' > /tmp/chat.out 2>&1; grep -c {REPLY} /tmp/chat.out", timeout=300)
    with open(f"{COLD}/record.py", "w") as f:
        f.write(RECORD)
    out = exec_sh("python3 -", timeout=600, stdin_file=f"{COLD}/record.py")["stdout"]
    lines = out.splitlines()
    print(lines[0])
    with open(f"{COLD}/working-set-{kind}.txt", "w") as f:
        f.write("\n".join(l.split(" ", 2)[2] for l in lines[1:]) + "\n")
    with open(f"{COLD}/working-set-{kind}.summary", "w") as f:
        f.write(out)
    if stop_hermes(kind) is not None and kind != "gateway":
        sleep_disk()
    kill_all()
    p.wait(timeout=30)


def main():
    a = sys.argv[1:]
    os.makedirs(COLD, exist_ok=True)
    if a[0] == "record":
        record(a[1])
    elif a[0] == "trace":
        sample("chat", a[1], a[2:], 0, trace=True)
    else:
        for i in range(int(a[2])):
            sample(a[0], a[1], a[3:], i)


if __name__ == "__main__":
    main()
