# Imported source versions

This integrated repository was assembled on 2026-08-23 from these clean source
trees:

| Component | Source repository | Branch | Commit |
| --- | --- | --- | --- |
| XrayR service | `https://github.com/liyansum/XrayR` | `master` | `a9df56584ebd97b68e6987fcf2cd207cbbc27d3f` |
| Dedicated Xray core | `https://github.com/liyansum/Xray-core` | `main` | `f5b4e833af34694c4b936629591c52c7c49cef91` |

The service module path was changed to `github.com/liyansum/Xray`. The core
keeps the canonical `github.com/xtls/xray-core` module path and is selected by
the parent module's local `replace` directive.
