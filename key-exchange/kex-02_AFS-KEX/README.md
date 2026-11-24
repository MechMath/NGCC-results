# kex-02: AFS-KEX

- Severity: **Medium**
- Evidence status: **Proof gap**
- Layer: **Implementation**

## Result

AFS-KEX 实现预置组合公钥，缺少证明要求的每会话新鲜公钥传输，PFS 论证不能直接覆盖。

## Scope and conditions

未证明 PFS/密钥保密实际破坏。
