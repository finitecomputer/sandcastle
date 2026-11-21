# Every .py under the image root's /opt/hermes: is its bytecode cache present
# and valid for Python 3.14 (magic, then the source time and size it
# records, or a hash-based pyc)? Run by the image's own python against the
# image mounted read-only on the parent.
import importlib.util, os, sys, collections, struct
root = sys.argv[1]
magic = importlib.util.MAGIC_NUMBER
c = collections.Counter(); where = collections.Counter(); stale = []
for dp, dns, fns in os.walk(os.path.join(root, "opt/hermes")):
    if "__pycache__" in dp:
        continue
    for f in fns:
        if not f.endswith(".py"):
            continue
        p = os.path.join(dp, f)
        try:
            st = os.stat(p)
        except OSError:
            c["unreadable"] += 1; continue
        pyc = importlib.util.cache_from_source(p)
        top = os.path.relpath(p, root).split("/")[:3]
        try:
            h = open(pyc, "rb").read(16)
        except OSError:
            c["missing"] += 1; where["/".join(top)] += 1; continue
        if h[:4] != magic:
            c["other magic"] += 1; continue
        flags = struct.unpack("<I", h[4:8])[0]
        if flags & 1:
            c["hash-based, checked" if flags & 2 else "hash-based, unchecked"] += 1; continue
        mtime, size = struct.unpack("<II", h[8:16])
        if mtime == (int(st.st_mtime) & 0xFFFFFFFF) and size == (st.st_size & 0xFFFFFFFF):
            c["valid (time and size match)"] += 1
        else:
            c["stale (time or size differ)"] += 1
            if len(stale) < 5: stale.append((os.path.relpath(p, root), mtime, int(st.st_mtime), size, st.st_size))
print("python", sys.version.split()[0], "magic", magic.hex())
for k, v in c.most_common(): print(f"{v:7}  {k}")
print("missing, by directory:", where.most_common(8))
print("stale, first:", stale)
