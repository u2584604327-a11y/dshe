# DSH → OmniGate：原版最小链路实机核查（不改既有引擎）

## 已确定的接线决策

保留原版 DSH 的 `dsh-llm-pi-ai`、`dsh-api-session-controller`、`dsh-client-ui-chat`、Cordis 会话投影和工具机制。用户唯一的消息输入在 DSH。原版模型适配器使用现有 OpenAI-compatible provider，不增加新的聊天 UI、SSE 客户端或云端中转。

候选连接：
`DSH 原版消息 → pi-ai 模型适配器 → http://127.0.0.1:8787/v1 → OmniGate → 原版 Native API`。

重要：P90 只适用于 OmniGate **网页气泡插入/发送**，不能作为 DSH 原版模型适配器是否准许发起 HTTP 请求的前置条件。**已在 P92 原候选类中纠正此混用**：网页气泡路径保留原 P90 输入框核验；原版模型路径使用 `P92DshRouteGate.forOriginalProviderTurn(turnId, trustedOriginalSessionCallback)`，要求来自原版会话控制器的当前有效用户 turn、在实际尝试发送前再次核验、以及现有原版 8787/Native owner 验证。原版 API 路径不做网页气泡点击，不因网页 `len=0` 被阻断。HTTP200 与已接受的用户 turn **仅证明请求初步接受，不证明模型已经回复**。`OriginalSessionTurn` 为待接入原版运行时的接口，当前仍只是在隔离源码里编译和测试，**未上线**；禁止把外部任意 boolean、JS 消息或模型输出伪装成可信会话回执。保留 P90 的网页虚假 SENT 防护。

## 使用当前可执行只读检查

在实际负责模型 HTTP 调用的 **原版 DSH Node 进程运行环境** 中执行：

```sh
node omnigate_local_preflight.mjs
```

文件位于本目录。需要先把文件放入该 Node 环境可读的路径。如果当前 DSH 仅允许受限制的工具或不存在终端，**不可假设上述命令能执行**，不得偷偷解除沙箱、修改原版引擎或私自启用高权限。

脚本只请求 `GET http://127.0.0.1:8787/health`；只有主/悬浮运行时所有者已被验证，才继续只读 `GET /v1/models`。固定占位符只用于本地模型列表读取，不读取或打印真实 API key、Cookie 或模型名称。永不 POST、发送用户提示词、自动重试、停止正在生成的模型或重启原版服务。CLI 的固定端口为 8787；代码里的端口参数只用于离线单元测试。

判读：
- `READONLY_LOCAL_API_READY_NOT_MODEL_TURN_PROOF`：只证明本次健康检查和模型列表读取成功；**不证明 DSH 已收到模型回复**。后续需单次、用户主动发起的 DSH 聊天及工具调用实机验证。
- `NATIVE_OWNER_UNVERIFIED_NO_POST`：预估后续 POST 可能被 409 拒绝；保留原版网页和端口，先核实 OmniGate 对主/悬浮 WebDriver 的真实归属，不绕过 409。
- `ISOLATED_LOOPBACK_DENIED`：本次运行 Node 无权限访问 loopback。已知 P31 隔离 UID 下 TCP 曾返回 EACCES；这不表示应放宽隔离网络权限。未来需要可信 Android 宿主进程的严格白名单本地 API Broker，且只转发经过授权、与当前原版会话关联的请求。当前尚未接线。
- `LOCAL_LISTENER_MISSING`、`LOCAL_LISTENER_TIMEOUT`：需要排查同设备监听器和应用存活；不得自行重启正在执行中的模型。
- `MODEL_CATALOG_EMPTY_OR_INVALID` 或 `MODELS_HTTP_NON200`：即使健康检查通过，模型配置仍不可用。此状态不许写成成功。
- `UPSTREAM_UNREACHABLE_OR_UNKNOWN`：原版 Native API 不可达；没有确认属于当前 MainActivity 或 OverlayService 的监听者。

## 原版 UI 的后续用户授权实验

仅在空闲、没有正在生成的对话时，使用 DSH **原有模型设置** 选择/验证 OpenAI 兼容协议及 `http://127.0.0.1:8787/v1` 的 baseURL；以 UI 所支持的模型选择及凭证机制为准，不能凭静态字符串推定 UI 字段一定可编辑。不要修改原版模型 ID、配置库、数据库、登录状态或已有会话以强行使协议通过。

用户手动发起一条非工具普通短消息，必须依次核实：原版 DSH 会话实际记录用户 turn → OmniGate GET/POST 时 owner 路由匹配 → `/v1/chat/completions` 实际流经原版 Native API → 正常内容增量回到 DSH 现有消息投影 → 同一模型 turn 标记完成。随后另测工具返回继续生成，特别是拒绝发布评论时仍能得到类型化失败结果，不重复发出未经批准的评论。

## 不得误报

当前仅验证只读 Node 检查器及归档静态接口：未安装新的 DSH APK、没有证明 DSH 与 OmniGate 的实机完整模型调用、没有完成严格沙箱内的本地 API Broker、B站登录/评论、WebView 隐藏或自动换对话实机验收。原始签名、原版模型、3080、Native API 监听端口及 8787、Cookie/session 均保持不变。禁止生成正式 v139 APK 或合并该 Draft PR，直至原版节点真实调用和授权发布链路经过手机端验证。


## 原版 Pi-AI 模型路由配置（源码验证，不自动写入）

原版签名 v138 的 `@deepseek-ai/dsh-llm-pi-ai/lib/index.js` 已按 APK SHA256 和包内源文件 SHA256 检查：其路由 schema 明确存在 `displayName`、`api`、`baseURL`、`models`、`apiKeyEnv`（凭证引用）、`defaultContextWindow`、`defaultMaxTokens` 和 `defaultInput`。每个自定义模型必须具备真实的 `id`；`maxTokens`、`contextWindow` 不可假冒远端能力。

运行已有的离线纯 Node 配置生成器：

```sh
node original_dsh_omnigate_profile.mjs \
  --model-id "REPLACE_WITH_ACTUAL_MODEL_ID" \
  --context-window ACTUAL_VERIFIED_CONTEXT_CAPACITY \
  --max-tokens ACTUAL_VERIFIED_OUTPUT_CAPACITY
```

命令中的模型 ID 与两项容量必须换成从正在使用的模型提供方、设备端模型清单或官方说明**实际核验**的值；任意缺项、负数、越界或伪造凭证参数均拒绝输出。若 DSH 实际需要凭证映射，仅允许追加 `--credential-env OMNIGATE_LOCAL_API_KEY`，并从 DSH 原有受信凭证机制设置该环境变量。**不是把 API Key 的真实内容作为参数、写入仓库或粘贴到聊天。**

输出是原版 Pi-AI 的一个候选 *provider profile 对象*，**不是整个 DSH 设置文件**。它不自动导入、不自动增删配置、不能保证当前版本的设置 UI 具有粘贴该对象的入口。正式应用前必须验证原版 `dsh-llm-pi-ai` 插件的配置存储键和实际模型选择/修改 UI，采用原版配置流程并备份原设置；禁止通过猜测文件目录和覆盖用户数据强行安装配置。

生成器只声明 `input:["text"]`；原版图片/文件发送和工具结果能力均需独立确认，不可用“支持 OpenAI 兼容协议”推断已经打通。

源码校验与生成器回归记录：P96 现有 CI；未在用户手机运行，未连接当前 DSH Node 实际会话，未自动改变模型、OmniGate、沙箱、B站浏览器或登录信息。
