---
description: >-
  Tycho uses a specific address convention for native tokens that differs from
  some protocols.
---

# Native Token Handling

#### Address Convention

**Tycho reserves the zero address (`0x0000000000000000000000000000000000000000`) to represent the native token across all chains.**

Some protocols use `0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE` or other sentinel addresses for native tokens. If your protocol follows this pattern, you must normalize these addresses to the zero address in your Substreams package.
