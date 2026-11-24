# sign-12: Galas

- Severity: **Critical**
- Evidence status: **Confirmed**
- Layer: **Implementation**

## Result

普通 API 在可选 KAT 钩子未设定时固定零种子生成密钥，可公开再生并伪造。

## Scope and conditions

属于实现可预测初始化，不是攻击者额外重置 DRBG 的模型。
