# sign-07: CS

- Severity: **Critical**
- Evidence status: **Confirmed**
- Layer: **Implementation**

## Result

64 位长度截为 32 位；空消息签名可转用于未查询的 2^32 字节消息。

## Scope and conditions

所测原构建成立；
