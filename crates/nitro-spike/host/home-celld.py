#!/usr/bin/env python3
"""The home study (docs/nitro-spike.md, "A home: celld in a sandbox of
its own"), run on the parent as its build user:

  ./home-celld.py image                 # celld's root, then its verity image
  ./home-celld.py deploy                # host/home/worker into the fleet bucket
  ./home-celld.py lives <name> <n> [--mem-mib M] [--memory] [--shutdown-ms T]
  ./home-celld.py floor                 # the smallest sandbox that serves

Each life is a fresh confidential sandbox whose workload is celld alone
(home/home-entry.sh), its fleet bucket a real S3 bucket in us-east-2, the
parent's role credentials handed to it in the environment. The parent
talks to celld's public listener over the tap, as a front door would. A
life: launch, celld's health, the first answer from an object an earlier
life wrote (it must come back from the bucket), warm reads, one
acknowledged write, then a graceful stop (SIGTERM to celld); the next life
checks it reads that write. Results append to ~/home/results.jsonl.

Python, not Rust, for the reason cold-reads.py gives.
"""
import json
import os
import statistics
import subprocess
import sys
import time
import urllib.request

HOME = os.path.expanduser("~")
HERE = os.path.dirname(os.path.abspath(__file__))
BIN = f"{HOME}/sandcastle/target/release/sandcastle-nitro-spike"
CELLD = f"{HOME}/celld/target/release/celld"
OUT = f"{HOME}/home"
LOG = f"{OUT}/hold.log"
HELD = "/run/nitro-spike/held"
GUEST = "http://10.0.2.2:8080"
REGION = "us-east-2"
WAIT_S = 120
BUCKET = open(f"{HOME}/home/bucket").read().strip() if os.path.exists(f"{HOME}/home/bucket") else None
# debian:bookworm-slim for arm64, pinned by the digest pulled on 2026-11-21.
BASE = open(f"{HOME}/home/base-digest").read().strip() if os.path.exists(f"{HOME}/home/base-digest") else None


def run(cmd, timeout=600, **kw):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, **kw)
    if r.returncode != 0:
        raise RuntimeError(f"{cmd[:3]}: {r.stdout[-500:]} {r.stderr[-800:]}")
    return r.stdout


def imds_credentials():
    """The parent role's short-lived credentials, from its metadata service."""
    tok = urllib.request.urlopen(urllib.request.Request("http://169.254.169.254/latest/api/token", method="PUT", headers={"X-aws-ec2-metadata-token-ttl-seconds": "300"}), timeout=2).read().decode()
    h = {"X-aws-ec2-metadata-token": tok}
    role = urllib.request.urlopen(urllib.request.Request("http://169.254.169.254/latest/meta-data/iam/security-credentials/", headers=h), timeout=2).read().decode().strip()
    c = json.loads(urllib.request.urlopen(urllib.request.Request(f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role}", headers=h), timeout=2).read())
    return {"AWS_ACCESS_KEY_ID": c["AccessKeyId"], "AWS_SECRET_ACCESS_KEY": c["SecretAccessKey"], "AWS_SESSION_TOKEN": c["Token"]}


def image():
    os.makedirs(OUT, exist_ok=True)
    t0 = time.time()
    ref = "debian:bookworm-slim"
    run(["sudo", "docker", "pull", "--platform", "linux/arm64", "-q", ref])
    digest = run(["sudo", "docker", "image", "inspect", ref, "--format", "{{index .RepoDigests 0}}"]).strip()
    open(f"{OUT}/base-digest", "w").write(digest)
    ctx = f"{OUT}/context"
    os.makedirs(ctx, exist_ok=True)
    run(["cp", CELLD, f"{ctx}/celld"])
    run(["cp", f"{HERE}/home/Dockerfile", f"{ctx}/Dockerfile"])
    run(["sudo", "docker", "build", "-q", "--platform", "linux/arm64", "--build-arg", f"BASE={digest}", "-t", "nitro-home", ctx], timeout=900)
    t1 = time.time()
    run(["sudo", "rm", "-rf", "--one-file-system", "/srv/celld-root"])
    run(["sudo", "mkdir", "-p", "/srv/celld-root"])
    cid = run(["sudo", "docker", "create", "--platform", "linux/arm64", "nitro-home"]).strip()
    subprocess.run(f"sudo docker export {cid} | sudo tar -x -C /srv/celld-root --numeric-owner", shell=True, check=True)
    run(["sudo", "docker", "rm", cid])
    cfg = json.loads(run(["sudo", "docker", "image", "inspect", "nitro-home", "--format", "{{json .Config}}"]))
    json.dump(cfg, open(f"{OUT}/celld-config.json", "w"))
    root_bytes = int(run(["sudo", "du", "-sb", "/srv/celld-root"]).split()[0])
    run(["sudo", f"{HOME}/sandcastle/crates/nitro-spike/host/verity-image.sh", "/srv/celld-root", f"{HOME}/nitro/image-extra", f"{HOME}/nitro/images/celld"], timeout=900)
    run(["sudo", "chown", "ec2-user:", f"{HOME}/nitro/images/celld.ext4", f"{HOME}/nitro/images/celld.verity", f"{HOME}/nitro/images/celld.json"])
    t2 = time.time()
    meta = json.load(open(f"{HOME}/nitro/images/celld.json"))
    row = {"step": "image", "base": digest.split("@")[1][:19], "build_s": round(t1 - t0, 1), "image_s": round(t2 - t1, 1), "root_bytes": root_bytes, "image_mib": meta["image_mib"], "celld_bytes": os.path.getsize(CELLD)}
    print(json.dumps(row))
    append(row)


def deploy():
    env = dict(os.environ, AWS_REGION=REGION, PATH=f"{HOME}/home/esbuild/package/bin:" + os.environ["PATH"])
    t0 = time.time()
    out = run([CELLD, "deploy", f"{HERE}/home/worker", "--bucket", f"s3://{BUCKET}", "--region", REGION], env=env)
    row = {"step": "deploy", "s": round(time.time() - t0, 2), "out": out.strip()[-300:]}
    print(json.dumps(row))
    append(row)


def append(row):
    with open(f"{OUT}/results.jsonl", "a") as f:
        f.write(json.dumps(row) + "\n")


def kill_all():
    for name in ["sandcastle-nitr", "firecracker"]:
        subprocess.run(["sudo", "pkill", "-x", name])
    for _ in range(200):
        if subprocess.run(["pgrep", "-x", "firecracker"], capture_output=True).returncode != 0:
            return
        time.sleep(0.05)
    raise RuntimeError("a Firecracker outlived its kill")


def line_at(text):
    """The driver's stamp (ms since Firecracker's spawn) of a guest line."""
    for l in open(LOG):
        if l.startswith("guest +") and text in l:
            return int(l.split("+", 1)[1].split(":", 1)[0])
    return None


def wait_line(text, deadline):
    while time.time() < deadline:
        if os.path.exists(LOG) and line_at(text) is not None:
            return line_at(text)
        time.sleep(0.01)
    raise RuntimeError(f"no {text!r}: {open(LOG).read()[-800:]}")


def http(method, path, timeout=10):
    req = urllib.request.Request(GUEST + path, method=method, data=b"" if method == "POST" else None)
    t = time.time()
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = r.read()
        return r.status, body, (time.time() - t) * 1000


def exec_sh(script, timeout=120):
    env = json.load(open(f"{OUT}/celld-config.json")).get("Env") or []
    cmd = ["sudo", BIN, "exec", "--dir", HELD] + [x for e in env for x in ("--env", e)] + ["--", "/bin/sh", "-c", script]
    return json.loads(run(cmd, timeout=timeout))["stdout"]


def rss():
    out = exec_sh("for p in $(pgrep -x celld); do grep -E 'VmRSS|VmHWM' /proc/$p/status; done; grep -E 'MemTotal|MemAvailable' /proc/meminfo")
    v = {}
    for l in out.splitlines():
        k, val = l.split(":", 1)
        v[k.strip()] = int(val.split()[0])
    return v


def life(name, index, expect, mem_mib, memory, shutdown_ms=None):
    kill_all()
    creds = imds_credentials()
    env = dict(creds, AWS_REGION=REGION, CELLD_BUCKET=f"s3://{BUCKET}")
    if shutdown_ms:
        env["CELLD_SHUTDOWN_TOTAL_MS"] = str(shutdown_ms)
    cmd = ["sudo", BIN, "hold", "--kernel", f"{HOME}/nitro/guest-kernel/out/Image", "--initrd", f"{HOME}/nitro/images/guest.initrd",
           "--image-json", f"{HOME}/nitro/images/celld.json", "--image-config", f"{OUT}/celld-config.json",
           "--mem-mib", str(mem_mib), "--scratch-gib", "4", "--entrypoint-file", f"{HERE}/home/home-entry.sh",
           "--allow", f"s3.{REGION}.amazonaws.com", "--allow", f"{BUCKET}.s3.{REGION}.amazonaws.com"]
    for k, v in env.items():
        cmd += ["--env", f"{k}={v}"]
    if os.path.exists(LOG):
        os.remove(LOG)
    t0 = time.time()
    p = subprocess.Popen(cmd, stdout=open(LOG, "w"), stderr=subprocess.STDOUT)
    deadline = time.time() + WAIT_S
    row = {"name": name, "life": index, "mem_mib": mem_mib, "shutdown_total_ms": shutdown_ms}
    row["started_ms"] = wait_line("nitro: started", deadline)
    row["time_ms"] = wait_line("nitro: time", deadline)
    # celld's health, asked every 10 ms from the parent.
    while True:
        try:
            if http("GET", "/.well-known/celld/health", timeout=2)[0] == 200:
                break
        except Exception:
            pass
        if time.time() > deadline:
            raise RuntimeError(f"no health: {open(LOG).read()[-1500:]}")
        time.sleep(0.01)
    row["health_ms"] = round((time.time() - t0) * 1000)
    status, body, ms = http("GET", "/?name=a")
    row["restored_ms"] = round((time.time() - t0) * 1000)
    row["restored_request_ms"] = round(ms, 1)
    row["restored_n"] = json.loads(body)["n"]
    row["expected_n"] = expect
    row["restored_right"] = expect is None or row["restored_n"] == expect
    warm = [http("GET", "/?name=a")[2] for _ in range(10)]
    row["warm_read_ms"] = {"median": round(statistics.median(warm), 2), "min": round(min(warm), 2), "max": round(max(warm), 2)}
    status, body, ms = http("POST", "/?name=a")
    row["write_ack_ms"] = round(ms, 1)
    row["acked_n"] = json.loads(body)["n"]
    if memory:
        m = {"idle": rss()}
        made = 1  # "a" is resident already
        for tier in (10, 100):
            while made < tier:
                http("GET", f"/?name=o{made}")
                made += 1
            m[str(tier)] = rss()
        m["1"] = m.pop("idle")
        row["memory_kib"] = m
    # The graceful stop: SIGTERM to celld, the workload's first process,
    # then Firecracker's exit when the guest powers off.
    t = time.time()
    row["sigterm_ms"] = round((t - t0) * 1000)
    try:
        exec_sh("kill -TERM 1", timeout=30)
    except Exception:
        pass
    try:
        p.wait(timeout=90)
    except subprocess.TimeoutExpired:
        row["stop_timed_out"] = True
    for _ in range(1800):
        if subprocess.run(["pgrep", "-x", "firecracker"], capture_output=True).returncode != 0:
            break
        time.sleep(0.05)
    row["stop_ms"] = round((time.time() - t) * 1000)
    row["stopped_cleanly"] = "Exited" in open(LOG).read()[-400:]
    # From celld's own log: its last durability barrier, and its exit.
    barriers = [int(l.split("+", 1)[1].split(":", 1)[0]) for l in open(LOG) if l.startswith("guest +") and "final durability barrier passed" in l]
    row["durable_after_sigterm_ms"] = (max(barriers) - row["sigterm_ms"]) if barriers else None
    row["ready_gate_waited_ms"] = next((int(l.split("waited_ms=")[1].split()[0]) for l in open(LOG) if "ready_gate_open" in l), None)
    kill_all()
    # What the next life must read: the write this life saw acknowledged.
    open(f"{OUT}/last-acked", "w").write(str(row["acked_n"]))
    append(row)
    print(json.dumps({k: row[k] for k in row if k != "memory_kib"}), flush=True)
    return row


def main():
    a = sys.argv[1:]
    os.makedirs(OUT, exist_ok=True)
    if a[0] == "image":
        image()
    elif a[0] == "deploy":
        deploy()
    elif a[0] == "lives":
        mem = int(a[a.index("--mem-mib") + 1]) if "--mem-mib" in a else 1024
        shutdown_ms = int(a[a.index("--shutdown-ms") + 1]) if "--shutdown-ms" in a else None
        expect = None
        last = f"{OUT}/last-acked"
        if os.path.exists(last):
            expect = int(open(last).read())
        for i in range(int(a[2])):
            row = life(a[1], i, expect, mem, "--memory" in a, shutdown_ms)
            if not row["restored_right"]:
                raise RuntimeError(f"life {i} read {row['restored_n']}, the last acknowledged write was {expect}")
            expect = row["acked_n"]
    elif a[0] == "floor":
        for mem in (256, 512, 1024):
            last = f"{OUT}/last-acked"
            try:
                life("floor", 0, int(open(last).read()) if os.path.exists(last) else None, mem, True)
            except Exception as e:
                append({"name": "floor", "mem_mib": mem, "failed": str(e)[-600:]})
                print(json.dumps({"floor": mem, "failed": str(e)[-300:]}), flush=True)
                kill_all()


if __name__ == "__main__":
    main()
