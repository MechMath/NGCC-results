# sign-09: DOVE

- Severity: **Low**
- Evidence status: **Confirmed**
- Layer: **Implementation**

## Result

正常签名从精确 24 字节密钥缓冲区外读取 2992 字节，guard/ASan 终止。

## Scope and conditions

仅有越界读和可用性后果，未证明秘密泄露。
