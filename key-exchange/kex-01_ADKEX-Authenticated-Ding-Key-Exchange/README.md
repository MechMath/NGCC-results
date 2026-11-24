# kex-01: ADKEX (Authenticated Ding Key Exchange)

- Severity: **Medium**
- Evidence status: **Proof gap**
- Layer: **Design**

## Result

ADKEX 打印的安全游戏允许 Test 后 Corrupt，产生模型定义反例；另有无匹配响应者的窄完成行为。

## Scope and conditions

这不是在标准新鲜性模型下的完整协议攻击；普通线性重放负载不构成拒绝服务发现。
