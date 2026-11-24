# kem-01: Aigis-Enc+

- Severity: **Critical**
- Evidence status: **Confirmed**
- Layer: **Implementation**

## Result

Aigis-Enc+ 失败的重加密比较未改变调用者的密钥输出，600/600 所测修改返回挑战密钥。

## Scope and conditions

Reference/AVX2 I/II/III 的有限见证；不声称所有随机密钥均成功。
