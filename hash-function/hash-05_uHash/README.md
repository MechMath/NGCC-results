# hash-05: uHash

- Severity: **Critical**
- Evidence status: **Confirmed**
- Layer: **Design**

## Result

uHash-512 在论文经典理想密码模型内，指定合法超长消息的第二原像可用至多 2^464 调用完成。

## Scope and conditions

模型内已证明、非实际执行；内存 O(2^264) 个 512 位状态。
