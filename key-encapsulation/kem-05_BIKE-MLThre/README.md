# kem-05: BIKE-MLThre

- Severity: **Info**
- Evidence status: **Confirmed**
- Layer: **Evaluation**

## Result

BIKE-MLThre 的移位未定义行为仅在强制 UBSan trap 构建中终止。

## Scope and conditions

普通构建未证明崩溃、输出分歧或安全后果，按当前规则未达到 Low。
