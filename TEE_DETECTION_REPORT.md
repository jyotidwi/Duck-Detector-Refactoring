# Duck Detector TEE 检测总结报告

## 报告目的

本文档用于独立总结Duck Detector项目当前的 TEE 检测体系，不讨论源码位置，不引用实现文件，只描述检测能力本身。

本文重点回答五件事：

- 检测项是什么
- 它实际在检查什么
- 原理是什么
- 它属于什么证据层级
- 它会不会影响最终 verdict，以及默认显示成红、黄还是仅展示

## 总体判定口径

本项目的 TEE 模块不是“读一次 attestation 就出结论”的单点判定器，而是一个多层证据融合器。它同时做三类事情：

- 验证官方 attestation 与证书链语义是否自洽
- 验证 attested boot / provisioning / revocation 与本地运行态是否一致
- 用普通 app 可做到的本地行为学与 native 对抗探针，复演 AndroidKeyStore 的非对称与对称路径，并检查运行时有没有被中间层、hook
  层或仿真层介入

因此，它内部的证据不是一个档次。

## 证据层级定义

| 证据层级    | 含义                                                                                                          |
|---------|-------------------------------------------------------------------------------------------------------------|
| 官方硬证据   | 直接来自证书链、challenge、吊销状态、RootOfTrust 与运行时 boot 信息的硬矛盾。这类命中最接近 Android / Google 官方语义。                          |
| 官方复核证据  | 仍然来自 attestation / provisioning / chain structure，但更偏结构异常、布局异常、策略复核项，不如硬矛盾那样绝对。                             |
| 本地强补充证据 | 普通 app 在本地复演 AndroidKeyStore / Keystore2 / native 调用语义后得到的强异常。它们很能说明“当前运行态不干净”，但不等同于官方 attestation 已被密码学推翻。 |
| 本地弱补充证据 | 时序、差异、资源约束、辅助环境痕迹、厂商生态信号等，偏审查线索。                                                                            |
| 上下文展示   | 用于说明状态、能力、链路属性或设备背景，本身不作为负面判定依据。                                                                            |

## Verdict 影响规则

| 类型                  | 作用                                                     |
|---------------------|--------------------------------------------------------|
| 直接影响硬负面 verdict     | 会把结果直接推向硬负面结论。                                         |
| 直接影响 review verdict | 会把结果推向需要复核、可疑、需审查的结论。                                  |
| 不直接改 verdict        | 不会单独推翻一条已经对齐的官方 attestation 路径，但会提高可疑度、提高分数、改变摘要与审查口径。 |

## Tier 口径

- 基础 tier 来自 attestation 自身声明的 security level。
- `TEE` 与 `STRONGBOX` 视为硬件层级。
- `SOFTWARE` 与 `NONE` 不会被本地侧证据强行升级成硬件层级。
- StrongBox 相关探针只用于精细化确认已经成立的硬件层级，不用于把软件级结果硬改成 StrongBox。

## 检测矩阵

### A. Attestation 与信任链

| 检测项                  | 原理                                                                                                                                       | 证据层级   | 是否影响 verdict                                  | 红/黄/仅展示 |
|----------------------|------------------------------------------------------------------------------------------------------------------------------------------|--------|-----------------------------------------------|---------|
| Attestation tier 提取  | 从证书链中的 Android key attestation 扩展读取 attestation security level 与 keymaster security level。它不是启发式推测，而是读取 attested key 自报的安全层级。            | 上下文展示  | 是。它决定基础 tier，并参与硬件是否成立这类基础结论。                 | 仅展示     |
| Challenge 匹配         | 本地先生成随机 challenge，再请求平台生成 attestation，最后把证书里取出的 challenge 与本地原值逐字节比较。若不匹配，说明这条 attestation 不是对当前请求的真实响应。                                 | 官方硬证据  | 是。可直接推动硬负面 verdict。                           | 红       |
| 本地证书链验签              | 对整条链逐级做本地验签，并让链尾根证书自验。若任何一级签名对不上，说明这条链在密码学上本身不成立。                                                                                        | 官方硬证据  | 是。可直接推动硬负面 verdict。                           | 红       |
| 信任锚归类                | 将链尾根证书与内置的 Google attestation roots 对比；若不匹配，再按 Android software attestation 常见主题与签发者模式归类为 AOSP 或 factory-style。它用于判断“这条链属于哪种根”，而不是直接判造假。 | 官方复核证据 | 间接影响。影响 trust summary 与整体可信度，但不是单独 hard fail。 | 黄或仅展示   |
| Issuer 路径连续性         | 检查每一张证书的 issuer 是否等于下一张证书的 subject。若链式衔接不连续，说明链布局不自然，需要复核。                                                                               | 官方复核证据 | 是。可把结果拉到 review。                              | 黄       |
| 证书有效期状态              | 检查链中每一张证书是否过期、未生效或时间异常。它不一定等价于篡改，但会削弱整条链的可信度。                                                                                            | 官方复核证据 | 是。可把结果拉到 review。                              | 黄       |
| 链长与 attestation 扩展计数 | 统计链长度、attestation 扩展出现次数、可信 attestation certificate 所在位置，判断它是否像一条标准 Android attestation chain。                                           | 上下文展示  | 否。当前主要用于展示与解释。                                | 仅展示     |

### B. RKP、吊销与 Boot 一致性

| 检测项                                      | 原理                                                                                                                            | 证据层级   | 是否影响 verdict                        | 红/黄/仅展示 |
|------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------|--------|-------------------------------------|---------|
| Provisioning info 存在性与邻接关系               | 在链中查找 provisioning info 扩展，并检查它是否紧邻可信 attestation certificate。对 RKP 而言，扩展有没有、位置是否正常，都很关键。位置错位通常意味着 provisioning 语义不完整或链布局不自然。 | 官方复核证据 | 是。可把结果拉到 review。                    | 黄       |
| RKP 与 Google 根一致性                        | 若链里存在 provisioning info，却没有落到 Google attestation root 上，说明“看起来像 RKP，但又不真正对齐 Google provisioning 链路”，属于明显结构矛盾。                 | 官方复核证据 | 是。可把结果拉到 review。                    | 黄       |
| RKP 负载解析                                 | 对 provisioning info 的 DER/CBOR 负载做解析，抽取 validated entity、短期证书有效期、发放量等信息，用于确认这是不是一条合理的远程 provisioning 产物。                      | 上下文展示  | 否。主要用于说明 provisioning 属性。           | 仅展示     |
| 在线吊销检查                                   | 拉取官方 attestation revocation feed，用证书 serial 去匹配 revoked 或 suspended 条目。若命中，说明这条链在官方吊销数据里已有明确负面状态。                             | 官方硬证据  | 是。可直接推动硬负面 verdict。                 | 红       |
| Attested boot hash 与运行时 vbmeta digest 对比 | 从 RootOfTrust 取 verifiedBootHash，再与运行时暴露的 vbmeta digest 对比。若两者矛盾，说明“attested 启动状态”和“当前系统暴露的启动元数据”不能同时成立。                      | 官方硬证据  | 是。可直接推动硬负面 verdict。                 | 红       |
| Attested boot hash 有值但运行时 digest 缺失      | 当 attestation 明确给出了 verifiedBootHash，而运行时拿不到对应 vbmeta digest，这是一种异常的不对称。它在当前口径里被视为硬矛盾。                                        | 官方硬证据  | 是。可直接推动硬负面 verdict。                 | 红       |
| verifiedBootHash 全零                      | 对于应当可比较的 boot state，如果 attested verifiedBootHash 为全零，通常不符合正常已验证启动的期望。                                                         | 官方硬证据  | 是。可直接推动硬负面 verdict。                 | 红       |
| verifiedBootKey 全零                       | 若 attested verifiedBootKey 为全零，也说明 RootOfTrust 关键字段不自然。                                                                       | 官方硬证据  | 是。可直接推动硬负面 verdict。                 | 红       |
| Patch level 漂移                           | 比较运行时安全补丁级别与 attestation 中的 OS patch level，并按月份距离分级。它反映的是“当前系统补丁态”与“attested 补丁态”是否贴合，更偏策略复核项。                                | 官方复核证据 | 当前主要用于展示和评分，不直接改 hard/soft verdict。 | 黄或仅展示   |

### C. Attested 设备、应用与 Key 声明

| 检测项                       | 原理                                                                                                                            | 证据层级    | 是否影响 verdict                  | 红/黄/仅展示 |
|---------------------------|-------------------------------------------------------------------------------------------------------------------------------|---------|-------------------------------|---------|
| Verified Boot State 展示    | 展示 RootOfTrust 中的 verified boot state 与 device lock state，用于解释 attestation 自报的启动状态。                                           | 上下文展示   | 间接影响。与 boot consistency 结合解释。 | 仅展示     |
| Device ID 抽取              | 从 attestation 扩展提取 brand、device、product、manufacturer、model、serial、IMEI、MEID 等标识。它首先是在读取 attested claims，而不是直接判异常。             | 上下文展示   | 否。                            | 仅展示     |
| Attested Key Properties   | 读取 algorithm、key size、curve、purpose、digest、padding、origin、rollback resistance 等属性，用于说明被 attested key 自身的能力声明。                 | 上下文展示   | 否。                            | 仅展示     |
| Attested User Auth State  | 读取 no-auth-required、user auth types、timeout、trusted confirmation、trusted presence、unlocked device required 等标签，反映该 key 的授权语义。 | 上下文展示   | 否。                            | 仅展示     |
| Attested Application Info | 读取 attested package names 与签名摘要，说明这条 attestation 把谁当作请求方。                                                                     | 上下文展示   | 否。                            | 仅展示     |
| ID Attestation 一致性        | 将 attestation 中可比较的设备标识与当前运行时 `Build` 字段逐项比较。若不一致，说明 attested device identity 与当前运行设备身份存在偏差，但它更像复核项，因为并非所有设备都会完整暴露这些字段。       | 本地弱补充证据 | 否。当前不直接改 verdict。             | 黄       |

### D. 本地 Keystore 语义探针

| 检测项                     | 原理                                                                                                                                                                           | 证据层级    | 是否影响 verdict                                     | 红/黄/仅展示 |
|-------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------|--------------------------------------------------|---------|
| Key Pair 一致性            | 本地创建新的签名 key，用私钥签名，再用叶证书公钥验签。若证书公钥无法验证刚生成的本地签名，说明“证书声明的 key”和“实际用于操作的 key”不一致。                                                                                               | 本地强补充证据 | 否。作为 supplementary evidence，不单独推翻官方 attestation。 | 红       |
| AES-GCM 对称密钥往返          | 本地生成新的 AndroidKeyStore AES key，并立即执行一次 `AES/GCM/NoPadding` 加密解密往返。若一把刚生成的对称 key 都不能完成原生往返，说明对称 keystore 操作路径可能被中间层接管、软件化替代，或实现出现异常。                                          | 本地强补充证据 | 否。作为 supplementary evidence。                     | 红       |
| AES KeyInfo 硬件级别        | 对同一把本地生成的 AES key 读取 KeyInfo 的 security level / secure hardware 信息，判断它是不是明确落在 StrongBox、TEE 或至少 secure hardware 上。若 AES key 只表现为 software-backed，说明对称 keystore 路径没有落到预期硬件级别。 | 本地弱补充证据 | 否。当前作为 local review signal，不直接改 verdict。         | 黄       |
| Key 生命周期语义              | 创建 key、删除 alias、再用同名 alias 重建，检查删除是否真实生效，以及重建后证书材料是否刷新。若生命周期行为不符合原生 AndroidKeyStore 语义，说明可能存在中间层接管。                                                                          | 本地强补充证据 | 否。作为 supplementary evidence。                     | 红       |
| 纯证书条目语义                 | 将仅含证书的条目写入 keystore，再调用 `getKey()`。原生语义下，证书条目不应返回私钥对象；若返回了 key，说明 keystore 语义偏离正常实现。                                                                                         | 本地强补充证据 | 否。作为 supplementary evidence。                     | 红       |
| 更新路径语义                  | 对已有 alias 走一次更新路径，观察是否抛出“key not found”风格异常。若底层对已存在 key 的更新表现得像“对象突然不存在”，很像代理层、镜像层或转译层实现不完整。                                                                                 | 本地强补充证据 | 否。作为 supplementary evidence。                     | 红       |
| Keybox 导入标记保持性          | 注入带自定义 marker subject 的导入证书，再看读回来的证书 subject 是否被替换。若 marker 被重写，说明底层不是透明保存导入材料，而是在重签、包裹或改写证书内容。                                                                              | 本地强补充证据 | 否。作为 supplementary evidence。                     | 红       |
| Keystore2 原始回复指纹        | 直接对 Keystore2 binder 发低层事务，请求一个不存在的 key，再根据 Parcel 序列化指纹判断返回的是原生风格还是 Java-hook 风格。它本质上是在测错误路径的底层序列化形态有没有被高层代理重写。                                                             | 本地强补充证据 | 否。作为 supplementary evidence。                     | 红       |
| Timing 异常               | 对本地签名操作做多次采样，观察中位数、离散度与抖动。若速度异常快且异常稳，可能说明并不是真实硬件路径，而是被代理、缓存或软件化处理。                                                                                                           | 本地弱补充证据 | 否。当前只作 review。                                   | 黄       |
| Oversized Challenge 接受性 | 用明显过大的 challenge 请求 attestation。若底层照单全收，说明它没有表现出预期约束行为，更像宽松转译或非标准实现。                                                                                                         | 官方复核证据  | 是。可把结果拉到 review。                                 | 黄       |
| Operation Pruning 行为    | 同时打开一批签名操作，观察系统是否会出现句柄淘汰、失效或资源约束。若在高并发下完全没有操作被剪枝，这种“过于宽松”的行为会被视为可疑，但仍属于行为学线索。                                                                                                | 本地弱补充证据 | 否。当前只作 review 展示。                                | 黄或仅展示   |
| 双算法链路对齐                 | 在同一环境下分别取 RSA 与 EC attestation chain，比对 issuer、trust root、chain length 是否一致。若两种算法返回的链结构风格明显不同，说明平台 attestation 路径不稳定。                                                        | 本地弱补充证据 | 否。当前主要展示。                                        | 黄或仅展示   |

### E. Native 运行态对抗探针

| 检测项                            | 原理                                                                                                                                 | 证据层级    | 是否影响 verdict                 | 红/黄/仅展示 |
|--------------------------------|------------------------------------------------------------------------------------------------------------------------------------|---------|------------------------------|---------|
| 可疑进程映射                         | 扫描当前进程的 `/proc/self/maps`，查找与 keystore spoof、TrickyStore、keybox interception、bootloader spoof 等相关的映射名称。它不是密码学矛盾，而是运行态环境被污染的痕迹。     | 本地弱补充证据 | 否。主要作为本地审查线索。                | 黄       |
| Tracing 检查                     | 读取 `TracerPid`，判断当前进程是否正在被外部跟踪。被跟踪不等于篡改，但它是解释 native 探针结果的重要上下文。                                                                   | 本地弱补充证据 | 否。主要展示或 review。              | 黄或仅展示   |
| Leaf DER 一类命中                  | 直接扫描叶证书 DER 原始字节，寻找高度可疑的模板化痕迹，例如固定长度十六进制模板串。这更接近“产物指纹命中”，属于强本地证据。                                                                  | 本地强补充证据 | 否。作为 supplementary evidence。 | 红       |
| Leaf DER 二类异常                  | 对 DER TLV 结构做递归解析，识别非最小长度编码、顶层序列不合法、树解析失败等异常。它说明 DER 结构“不够像标准产物”，但没有一类命中那么直接。                                                      | 本地弱补充证据 | 否。当前只作 review。               | 黄       |
| `ioctl` GOT Hook               | 对比 `libbinder` 中 `ioctl` 的 GOT 解析结果与 libc 真正 `ioctl` 地址。若 GOT 已被改写到别处，说明 binder 关键调用路径被中间层重定向。                                     | 本地强补充证据 | 否。作为 supplementary evidence。 | 红       |
| `ioctl` Inline Hook            | 对比内存中的 `ioctl` 前导指令与磁盘映像，并额外识别跳到其他库的 trampoline 或 BR 跳板。若存在差异，说明关键系统调用路径可能被 inline patch。                                          | 本地强补充证据 | 否。作为 supplementary evidence。 | 红       |
| Raw syscall 与 libc `ioctl` 不一致 | 对 binder 版本查询同时走 raw syscall 路径与 libc 包装路径，并重复多次。若两者在至少 `2/3` 轮中持续表现不一致，说明 libc 路径可能被包裹、拦截或转译。                                     | 本地弱补充证据 | 否。当前只作 review/context。       | 黄       |
| Binder 蜜罐时序异常                  | 构造类 keystore 的 binder 负载，同时比较 raw syscall 路径与正常调用路径的时间特征，并做多轮重复。若至少 `2/3` 轮稳定异常，说明某条路径可能被额外逻辑钩住。                                   | 本地强补充证据 | 否。作为 supplementary evidence。 | 红       |
| TrickyStore 运行态聚合命中            | 当 maps 命中、GOT hook、inline hook、honeypot 等 native 方法出现强命中时，聚合成运行态 spoof/hook 证据。它反映的是“当前进程正被某类中间层影响”，而不是直接推翻官方 attestation 的密码学成立性。 | 本地强补充证据 | 否。作为 supplementary evidence。 | 红       |

### F. StrongBox 扩展判定

| 检测项                            | 原理                                                                                                                     | 证据层级    | 是否影响 verdict                                       | 红/黄/仅展示 |
|--------------------------------|------------------------------------------------------------------------------------------------------------------------|---------|----------------------------------------------------|---------|
| StrongBox 能力宣告                 | 查询设备是否宣称具备 StrongBox keystore 功能。它只是能力前提，不代表当前 attestation 一定来自 StrongBox。                                             | 上下文展示   | 间接影响。用于解释是否应继续做 StrongBox 深探针。                     | 仅展示     |
| StrongBox Key 生成与本地 KeyInfo 级别 | 实际申请 StrongBox-backed key，再从本地 key metadata 中读取 security level。它看的不是“系统说支持 StrongBox”，而是“当前 app 是否真能拿到 StrongBox key”。 | 本地强补充证据 | 间接影响。可用于把已是 TEE 的结果精细化提升为 StrongBox。               | 黄或仅展示   |
| StrongBox Attestation 一致性      | 将 StrongBox 请求得到的 attestation tier 与本地 KeyInfo security level 做交叉验证。若一边声称是 StrongBox，另一边证实不了，就是明显不一致。                  | 本地强补充证据 | 不直接改主 verdict，但影响 effective tier 与 review summary。 | 黄       |
| StrongBox RSA-4096 接受性         | 观察 StrongBox 路径是否接受较不典型的大 RSA key 配置。它属于行为学 profile 检查，用于判断底层实现是否“过于宽松”或不像典型硬件。                                        | 本地弱补充证据 | 否。                                                 | 黄或仅展示   |
| StrongBox P-521 支持性            | 测试 StrongBox 是否接受 P-521 曲线，作为硬件行为特征之一。它更像 profile 信息，不是独立负面证据。                                                         | 上下文展示   | 否。                                                 | 仅展示     |
| StrongBox 签名时延                 | 测量 StrongBox 签名速度。若低到极不符合常见硬件路径的量级，会被视为可疑。                                                                             | 本地弱补充证据 | 否。                                                 | 黄       |
| StrongBox 生成时延                 | 测量 StrongBox 生成 key 的耗时。若过快，会被视为不够像真实独立安全芯片路径。                                                                         | 本地弱补充证据 | 否。                                                 | 黄       |
| StrongBox 并发句柄上限               | 同时创建大量签名句柄，观察底层是否表现出合理资源限制。该项更像 profile-based behavior check，用于识别“过于宽松”的实现。                                            | 本地弱补充证据 | 否。                                                 | 黄       |

### G. Soter 生态侧探针

| 检测项            | 原理                                                                     | 证据层级    | 是否影响 verdict                 | 红/黄/仅展示 |
|----------------|------------------------------------------------------------------------|---------|------------------------------|---------|
| Soter 预期支持模型   | 根据厂商品牌族谱判断设备理论上是否常见 Soter 支持。这不是 Android 官方 attestation 语义，而是厂商生态背景知识。 | 上下文展示   | 否。                           | 仅展示     |
| Soter 服务包存在性   | 检查 Soter 服务包是否存在，作为生态侧能力前提。                                            | 上下文展示   | 否。                           | 仅展示     |
| Soter 初始化与支持查询 | 尝试初始化 Soter SDK 并查询是否支持。若设备理论上应支持、服务也在，但初始化后却得不到支持，会被视为“生态能力损坏”。       | 本地强补充证据 | 否。作为 supplementary evidence。 | 红       |

## 哪些项会直接改变最终结论

### 会直接推动硬负面 verdict 的项

- Challenge 不匹配
- 本地证书链验签失败
- Attested boot hash 与运行时 vbmeta digest 矛盾
- Attested boot hash 有值但运行时 digest 缺失
- verifiedBootHash 全零
- verifiedBootKey 全零
- 官方吊销命中

### 会直接推动 review verdict 的项

- Issuer 路径不连续
- 证书有效期异常
- Provisioning 布局异常
- RKP 与根链路结构不一致
- Oversized Challenge 被接受

### 不会单独推翻 verdict、但会明显提高可疑度的项

- 本地 Keystore 语义探针
- Native anti-hook / anti-spoof 探针
- StrongBox 行为学异常
- Soter 损坏
- Timing 与 profile 类启发式探针

这些项虽然不单独改官方结论，但仍然重要，因为它们会：

- 提高本地 tamper / review 分数
- 改变卡片摘要
- 把“官方 attestation 对齐”改写成“官方 attestation 对齐，但本地仍需审查”

## 如何理解红、黄、仅展示

| 显示级别 | 解读方式                                    |
|------|-----------------------------------------|
| 红    | 要么是官方语义上的硬矛盾，要么是非常强的本地运行态异常，说明当前环境高度可疑。 |
| 黄    | 有结构异常、行为异常或需要人工复核的点，但还不足以单独推翻整条官方信任路径。  |
| 仅展示  | 主要是状态说明、能力说明、上下文说明或辅助理解信息。              |

## 总结

从整体上看，本项目的 TEE 模块不是只回答“这是不是 TEE”这一件事，而是在同时回答几组问题：

- Android attestation 自身是否成立
- 本地 trust path 是否成立
- Boot 与 revocation 语义是否成立
- AndroidKeyStore 的本地行为是否还像原生实现，包括非对称签名路径与对称 AES-GCM 路径
- 当前进程有没有被 hook、代理、spoof 或运行态中间层接管
- 如果声称是 StrongBox，本地行为是否还能支持这一点

因此，正确的理解方式不是“只看一个红点或绿点”，而是先区分它命中的是：

- 官方硬证据
- 官方复核证据
- 本地强补充证据
- 本地弱补充证据
- 还是仅用于解释背景的展示项

这也是本项目 TEE 卡片的真正设计哲学：不是做单点宣判，而是做分层、分强度、分语义来源的本地可信性审计。
