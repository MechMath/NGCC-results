# sign-19: Phoenix

- Severity: **Low**
- Evidence status: **Confirmed**
- Layer: **Implementation**

## Result

SM3-384f reference/AVX2 互操作不一致，并从 32 字节摘要读取 48 字节。

## Scope and conditions

不推断未证明的信息泄露或密钥恢复。
