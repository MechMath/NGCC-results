# kex-09: TriQ-KEX

- Severity: **Medium**
- Evidence status: **Confirmed**
- Layer: **Implementation**

## Result

TriQ-KEX 成功派生后保留完整会话秘密状态，违反规范要求的擦除，证明与实现不一致。

## Scope and conditions

额外内存披露才可重算密钥，非网络攻击；部分覆盖。
