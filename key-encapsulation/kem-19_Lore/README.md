# kem-19: Lore

- Severity: **Medium**
- Evidence status: **Proof gap**
- Layer: **Design**

## Result

Lore-384/512 将 256 位拒绝密钥空间误代入更大的消息空间，数值定理不能由所引 PRF 界推出。

## Scope and conditions

同时已确认原 API 内存越界 Low；恢复拒绝种子不等于 IND-CCA 破坏。
