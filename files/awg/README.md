# AmneziaWG packages

The role installs AmneziaWG from `ppa:amnezia/ppa` by default
(`kaskad_awg_packages_mode: ppa`). Use `local` mode only for hosts that cannot
reach `ppa.launchpadcontent.net`:

```bash
ansible-playbook playbooks/site.yml -e kaskad_awg_packages_mode=local
```

In `local` mode the role expects `.deb` files in this directory
(`files/awg/*.deb`); they are not committed to the repository. Download them
from the PPA pool for your Ubuntu release and place them next to this file:

| Package | Version used for `noble`/amd64 |
|---|---|
| `amneziawg` (meta) | `1.0.20210914-0~202608130144+ee0f0a9~ubuntu24.04.1` |
| `amneziawg-tools` | `1.0.20210914-0~202608130144+ee0f0a9~ubuntu24.04.1` |
| `amneziawg-dkms` | `1.0.0-0~202609061402+4569c4c~ubuntu24.04.1` |

`amneziawg-dkms` builds the kernel module `v3.1.20260906`,
`amneziawg-tools` corresponds to `v3.1.20260812`.

Verify checksums against the PPA `Packages.gz` index before installing.
