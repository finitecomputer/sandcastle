# The home study's workload start (docs/nitro-spike.md, "A home"): the clock
# from the NSM (S3's signatures need the time), then celld as the
# workload's first process, so a SIGTERM to it is the home's graceful stop.
# The fleet bucket and the credentials come from the parent, in the
# environment (CELLD_BUCKET, AWS_*): what this setup does not protect.
set -eu
echo 'nitro: started'
echo "nitro: time $(/opt/nitro/nitro-key settime)"
mkdir -p /var/lib/celld/state
export CELLD_WATCH=/var/lib/celld/state
exec /usr/local/bin/celld --listen 0.0.0.0:8080 --internal-listen 127.0.0.1:8081 --region us-east-2
