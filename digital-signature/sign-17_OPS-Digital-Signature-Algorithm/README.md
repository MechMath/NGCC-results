# sign-17: OPS Digital Signature Algorithm

- Severity: **Low**
- Evidence status: **Confirmed**
- Layer: **Implementation**

## Result

合法消息在分配失败时错误返回成功及零长度，另有互操作缺陷。

## Scope and conditions

并发 DRNG 数据竞争路线超出已支持模型，不用于升级。
