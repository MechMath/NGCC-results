# hash-19: MoFang Hash Function

- Severity: **Critical**
- Evidence status: **Lead**
- Layer: **Design**

## Result

MoFang 在布尔方程 S-box 及原始首半块 whitening 解释下存在零搜索完整哈希碰撞。

## Scope and conditions

Algorithm 1 类型错误使该解释未唯一确定；
