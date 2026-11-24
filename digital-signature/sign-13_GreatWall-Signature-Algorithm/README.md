# sign-13: GreatWall Signature Algorithm

- Severity: **Low**
- Evidence status: **Confirmed**
- Layer: **Implementation**

## Result

128s 拒绝特定等长签名时每次泄漏 720880 字节；源码及 LeakSanitizer 有控制证据。

## Scope and conditions

零密钥伪造在合法生命周期外；DRNG 接口前提未决，均不用于升级。
