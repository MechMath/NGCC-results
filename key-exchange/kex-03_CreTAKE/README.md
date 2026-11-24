# kex-03: CreTAKE

- Severity: **Low**
- Evidence status: **Confirmed**
- Layer: **Design**

## Result

CreTAKE 在复用 BiT 密钥于 S2S/S2K 角色时签名串无类型标记，可形成角色混淆。

## Scope and conditions

需要额外跨角色密钥复用；攻击者未学得会话密钥，不按普通单配置安全破坏评级。
