# hash-01: AFS-TrEDM

- Severity: **Low**
- Evidence status: **Confirmed**
- Layer: **Side-channel**

## Result

AFS-TrEDM 非字节对齐 framing 有消息相关分支，机器码保留；可用局部掩码消除。

## Scope and conditions

原 Medium；没有实测信道/提取，按当前局部修复规则改为 Low。
