# kem-04: BAG-Piglet

- Severity: **Low**
- Evidence status: **Confirmed**
- Layer: **Implementation**

## Result

BAG-Piglet 原 KDF 接线与规范不同，短密文长度被忽略导致越界读。

## Scope and conditions

没有密钥恢复或 IND-CCA 破坏；最终契约对应仍待修订。
