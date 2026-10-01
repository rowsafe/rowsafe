package protocol

// ReleaseInstallerKey is the key under which a release manifest lists the
// release's rendered installer (install.sh) in Artifacts, next to the agent
// builds ("linux/amd64", ...). The installer leaves a copy at
// /usr/local/lib/rowsafe/install.sh that `sudo rowsafe-allow` (and the
// one-click permission changes) run as root, and installs only a copy whose
// SHA-256 and size match this signed entry.
//
// It is an Artifacts entry rather than a field of its own so that agents
// released before it, which reject manifests with unknown fields but accept
// any artifact key, still verify and install new releases. An agent only
// ever reads its own platform's entry. Manifests from before it have no
// such entry and stay valid.
const ReleaseInstallerKey = "install.sh"
