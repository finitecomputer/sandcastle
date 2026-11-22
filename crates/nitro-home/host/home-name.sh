# Which home a parent's script acts on (docs/nitro-home.md, "Many homes
# on one parent"), sourced by home-stage.sh and home-switch.sh after
# `home_name "$@"`, which takes a leading `--home <name>` off the
# arguments (HOME_ARGS holds the rest):
#
#   no --home: the parent's one home, as it was before names: its slots in
#     /var/lib/nitro-home, its unit nitro-home.service;
#   --home <name>: one of several, its slots in
#     /var/lib/nitro-home/homes/<name>, its disks there too, its sockets in
#     /run/nitro-home/<name>, its unit nitro-home@<name>.service.
#
# A name is a DNS label of at most 32: lower-case letters, digits and
# inner hyphens (it is the home's host, `<name>.<parent's suffix>`).
HOMES=/var/lib/nitro-home/homes
home_name() {
    HOME_ARGS=("$@")
    if [ "${1:-}" = "--home" ]; then
        name=${2:?--home takes a name}
        [[ "$name" =~ ^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$ ]] || { echo "${0##*/}: $name: a name is a DNS label of at most 32 (a-z, 0-9, inner -)" >&2; exit 2; }
        base=$HOMES/$name
        unit=nitro-home@$name
        run=/run/nitro-home/$name
        HOME_ARGS=("${@:3}")
    else
        name=
        base=/var/lib/nitro-home
        unit=nitro-home
        run=
    fi
}
