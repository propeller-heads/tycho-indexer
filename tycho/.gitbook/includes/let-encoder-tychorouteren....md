---
title: let encoder = TychoRouterEn...
---

```rust
let encoder = TychoRouterEncoderBuilder::new()
    .chain(Chain::Ethereum)
    .swapper_pk(swapper_pk)
    .build()
    .expect("Failed to build encoder");
```
