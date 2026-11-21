# A guest with no door, one run

The engine of `nitro/home-no-door` on a parent (an m8g.xlarge, Amazon
Linux 2023), confidential sandboxes, its `kernel_args` set to
`sandcastle.agent=none sandcastle.start=image` (sessions off). The image:
celld's suite image plus `/etc/sandcastle/start.json`, which runs a Python
line printing "the image own start ran". Each start message named another
entrypoint: `sh -c "echo the parent entrypoint ran; sleep 600"`.

| | Result |
|---|---|
| What ran | the image's own start: its output `the image own start ran`; the parent's entrypoint never ran |
| The parent's exec, at the engine | **refused**: `400 {"error":"exec: this guest takes that only over its attested session, or not at all"}` |
| The parent's port 8080 | nothing listens (the suite's server, which the image would run by default, was never started) |
| The parent's signal | taken: the parent keeps stop and kill |
| The suite's image, with no start file | **refused its boot**: `the container failed: the kernel line names the image's start, and the image has no /etc/sandcastle/start.json` |
