# kem-02: Amoeba

- Severity: **Low**
- Evidence status: **Confirmed**
- Layer: **Implementation**

## Result

Amoeba-576 比较器漏字节、接受非规范密文，已执行发送方/接收方密钥不一致。

## Scope and conditions

密文进入最终 KDF，现有见证不能直接推出 IND-CCA 破坏。
