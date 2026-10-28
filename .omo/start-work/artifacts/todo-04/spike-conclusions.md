# Wave 0 todo 4 — XDispatchProviderInterceptor 拦截可行性 spike 结论

日期：2026-10-28 ｜ 环境：LO 26.8（专用 headless 实例 `cipherbox-spike4`，独立临时 profile，引擎经
components.rdb + unorc 注册，机制复制自 `start_soffice.ps1`）｜ 驱动：`lo-encryption-demo/test/spike_interceptor.py`
+ `run_spike_interceptor.ps1`（每 phase 全新实例 + 看门狗 + 文件直写 transcript，同目录 `transcript-p*.txt`）

**总体裁决：方案 A（LO 内拦截器）可行。** 拦截 SaveAs → 注入 `EncryptionData` → 产物为 CFB 密文且引擎 API
解密回环逐字节一致（OLE magic + 5 流 + `decrypt()` 验证，非"dispatch 返回即算"）。全部 9 个 phase 通过。

## 逐探针裁决矩阵

| # | 探针 | 裁决 | 机制与证据 |
|---|------|------|-----------|
| 1 | 注册 + queryDispatch 触发 | ✅ 可 | 经桥 `frame.registerDispatchProviderInterceptor(pyuno 对象)` 成功，frame 回写 slave；`DispatchHelper.executeDispatch(.uno:SaveAs)` 触发 queryDispatch→dispatch；吞掉后文档保持 modified（真拦截）。**前提：PyUNO 对象必须继承生成的接口类**（`XDispatchProviderInterceptor, XDispatch`），否则 `CannotConvertException`（P1 transcript） |
| 2a | SaveAs 预置描述符 + 委托 slave | ✅ 可 | URL/FilterName/Password/EncryptionData 预置后委托：**headless 无文件选择器、无挂起**；引擎 `encrypt()` 运行；产物 CFB 5 流 + 回环 OK；medium 切到 `.cbx`、doc 变 unmodified（真 SaveAs 语义）（P2 transcript） |
| 2b | 拦截器自执行 `storeToURL` | ✅ 可 | dispatch() 内 `model.storeToURL(target, [FilterName, Password, EncryptionData])` → CFB + 回环 OK；medium 不动（适合 SaveACopy/审计旁路语义）（P2） |
| 3 | 第二 frame | ✅ 按预期（每 frame 注册） | 仅在 frame1 注册时，frame2 的 SaveAs **dispatch 完全不经过** frame1 拦截器（`ic1.dispatches=[]`）；frame2 未拦截保存 = 明文 docx（PK magic）；在 frame2 补注册后立即被拦截吞掉。**附带重要发现：headless 下每个 frame 的链也有持续状态轮询流量（frame1 实测 135 次 queryDispatch，菜单/状态栏类命令）——queryDispatch ≠ 用户意图，只有 dispatch() 可行动**（P3） |
| 4 | 新 frame 发现 | ✅ 可（双通道） | 新文档：`Desktop.Components` 差集 +1、`Desktop.Frames.queryFrames(ALL)` 差集 +1、GlobalEventBroadcaster 触发 `OnCreate/OnNew/**OnViewCreated**/OnFocus` 等一串事件。同文档第二 view（Window>New Window 等价）headless 不可构造（`createViewController` 抛 "frame without container window not allowed"）——`OnViewCreated` 已对首个 view 实证；**不存在 `FRAME_CREATED` 枚举**（P4） |
| 5 | 反向 UNO 通道 | ✅ 可 | agent 侧 `unohelper.Base` 回调对象注册时传入、dispatch 路径中被调用（`getMasterKey`/`reportEvent` 均送达）；回调供给的口令驱动加密并回环验证；**管道桥 RTT 实测 0.24ms**——每次强制保存取钥 + 审计上报成本可忽略（P5） |
| 6 | SaveACopy | ✅ 可（需自存） | 可拦截（dispatch 到达）；但**预置描述符委托 slave = 静默无操作**（无产物、无异常、引擎未动——picker-bound 槽位，与 SaveAs 行为不同）；拦截器自存（2b 模式）产出验证过的 CFB 副本且 medium 不动（SaveACopy 语义保持）（P6） |
| 7 | SaveAs 后的 Save（关键） | ✅ 安全 | 强制 SaveAs 到 `.cbx` 后，后续 `.uno:Save` **原样委托**（不注入）产物仍是 CFB 5 流、可解密、含第二次编辑标记——**medium 自动保留 Password+EncryptionData，不会明文覆盖**。todo 17 优先级规则成立：`.cbx` 绑定文档的 `.uno:Save` 可放行（P7） |
| 8 | 导出/打印/发送族 | ✅ 全部可拦截；❌ 均不可注入 EncryptionData | 7 个 dispatch（ExportTo/ExportToPDF/ExportDirectToPDF/Print/PrintDefault/SendMail/SendDocAsPDF）**全部经过拦截链且 slave 均有处理器**。ExportDirectToPDF 实执行：产物明文 `%PDF-1.7`，EncryptionData 被忽略、引擎未参与（符合预期：该族不走包加密，只能放行+审计）。ExportTo/ExportToPDF 委托 headless 静默无操作（picker-bound 同类）；**ExportToPDF 预置 URL 不挂起**（静默返回无产物）。Print/SendMail 族仅做 queryDispatch 级探测（不触发真实打印/邮件副作用）（P8） |
| 9 | SaveAll 路由 | ✅ 可拦截（单 frame 路由） | SaveAll 只经过**被派发的那一个 frame 的链**（非广播：frame1 见、frame2 不见）；其触发的逐文档内部保存**不经过任何 frame 派发链**。另：**headless 下 SaveAll 功能惰性**——无拦截器时 frame 路由与 desktop 路由均不保存任何已修改文档（依赖可见 view shell；受控 GUI 实例有窗口，行为会不同）（P9） |

## 给 todo 17 的推荐机制

1. **注册点**：枚举 `Desktop.Components` 现有文档 → 每个 `doc.CurrentController.Frame` 调
   `registerDispatchProviderInterceptor`；新 frame 用 **GlobalEventBroadcaster 的 `OnViewCreated`（主）+
   `queryFrames(ALL)` 差集轮询（备，~2s 间隔）**。勿用不存在的 `FRAME_CREATED`。注意 `OnViewCreated` 在
   headless 仅对首 view 实证，第二 view 场景以轮询兜底。
2. **拦截动作分流**（dispatch() 内判断；queryDispatch 有状态轮询噪音，只用于宣称捕获，不做判断）：
   - `.uno:SaveAs` → 预置 URL(改 `.cbx`)+FilterName+Password+EncryptionData **委托 slave**（真 SaveAs 语义，
     medium 切换，headless 验证无选择器）；
   - `.uno:SaveACopy` → **拦截器自存**（storeToURL；委托无效已实证）；
   - `.uno:Save` → `.cbx` 绑定文档**直接放行**（medium 保留 EncryptionData，P7 实证不明文覆盖）；非 `.cbx`
     OOXML 文档按 todo 17 判定规则强制转 `.cbx`（自存 + 改 medium 或走 SaveAs 委托路径）；
   - `.uno:SaveAll` → 在拦截点**自行遍历 `Desktop.Components` 逐文档判定**（temp 文档放行写回临时明文；
     内部逐文档保存不再过链，无法依赖逐文档 `.uno:Save` 拦截）；
   - 导出/打印/发送族 → **只审计（reportEvent 回调 Agent，action=export_plaintext）后放行**；无一可注入
     EncryptionData。
3. **反向通道**：注册时把 agent 侧回调对象（PyUNO 接口对象 / XJob 式）传给拦截器；LO→agent 调用经管道桥
   XInvocation，RTT 0.24ms。取钥每次保存实时取（不持久持钥，取不到 fail-closed 拒存——与 todo 17 ①一致）；
   审计上报同通道，Agent 不可达时落 `S:\.cipherbox-tmp\audit-queue\`。
4. **驻留形态**：本 spike 拦截器在 agent 进程（桥反向调用实证可行）；todo 17 要驻留 LO 进程时，把拦截器
   Python 模块按引擎同法部署进受控 profile（components.rdb + unorc），回调对象仍是 agent 侧引用——
   两侧皆 Python，桥 XInvocation 动态调用成立（本 spike 两个方向均已实证）。

## 对抗性核查记录

- **hung_or_long_commands**：SaveAs 委托（P2a）、ExportToPDF（P8）均有 120s 看门狗；实测**均无挂起**；
  全部 phase 无看门狗击杀（transcript 无 RUNNER-WATCHDOG 行）；无遗留进程（runner 每 phase 杀自起实例并等退出）。
- **misleading_success_output**：所有"密文"断言均经 OLE magic + 5 流集合 + 引擎 `readEncryptionInfo/
  generateEncryptionKey/decrypt` + 标记字节回环验证；"保存发生"以文件字节变化/标记内容判定，非 dispatch 返回。
- **stale_state**：每 phase 全新实例（独立 profile，启动→跑→杀→等退出循环）；每探针全新文档。
- **flaky_tests**：P1（接口继承）、P4（XEventListener 命名空间 + createViewController 降级为 NOTE）、P6/P8
  （picker-bound 行为转记录为发现）、P7（脚本自身 note() 参数笔误）、P9（SaveAll 异步/惰性误判）各重跑 1 次；
  均为探针脚本修正，非被测机制不稳定；最终 9/9 PASS。
- prompt_injection / cancel_resume / dirty_worktree / repeated_interruptions：N/A（无外部输入文本、无会话中断、
  只新增本 spike 两个文件、单线程顺序执行）。

## 附：环境事实（供后续 worker 复用）

- headless 下：预置 URL 的 SaveAs 委托**无选择器无挂起**；SaveACopy/ExportTo/ExportToPDF 委托**静默无操作**
  （picker-bound）；SaveAll **功能惰性**（可见 view shell 依赖，GUI 实例正常）。
- 每个 frame 链的 queryDispatch 状态轮询噪音持续存在（headless 亦如此），拦截器 queryDispatch 必须廉价。
- 管道桥 RTT ≈0.24ms；GEB 文档事件在 `loadComponentFromURL` 返回后 ~1s 内异步到达。
- PyUNO 自定义接口对象必须继承 `com.sun.star.<module>.<Interface>` 生成类（`unohelper.Base` 在前）；
  GEB 的监听器接口是 `com.sun.star.document.XEventListener`（不是 `lang.XEventListener`）。
