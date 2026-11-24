# sign-22: Rhyme

- Severity: **Critical**
- Evidence status: **Confirmed**
- Layer: **Implementation**

## Result

Rhyme-SM3 缓冲溢出后消息摘要固定为零，一次长消息签名可用于不同未查询消息。

## Scope and conditions

实现限定；
