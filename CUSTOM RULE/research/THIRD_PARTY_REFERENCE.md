# Third-Party Research Reference

`research/wazuh_reference/` contains untouched Wazuh GPLv2 source excerpts that
were supplied only as design research. They are not application source, are not
imported, compiled, linked, packaged, or required at runtime, and are excluded
from version control/distribution by `.gitignore`.

The shipped implementation is an independent Python implementation using the
project's collector interface. Bookmark, registry, and inventory designs were
recreated in Python. File attribution is consumed passively from administrator-
enabled Security Event 4663; the application does not copy Wazuh whodata code or
alter audit policy/SACLs automatically.

Before distributing the workspace, omit `research/wazuh_reference/`. Wazuh
provenance and licensing remain governed by its upstream GPLv2 license.
