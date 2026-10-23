---
name: llm-redteam
description: LLM 应用安全红队评估：对已识别的 LLM 端点/应用做越狱、提示注入、数据泄露、越权等测试。仅在探索图中已存在 LLM 端点资产（fact.kind=llm_endpoint_entity）时由规划者调用，且同一端点的探测结果已记录（fact 含 llm_probe_result）时不再重复触发。
when:
  fact_exists: llm_endpoint_entity
  fact_missing: llm_probe_result
---

# LLM Red-team（大模型应用安全红队）

在**已授权**前提下，对探索图中已识别的 LLM 端点（`llm_endpoint_entity` 事实对应的资产）执行安全测试。

## 前置条件（由 Skill Matcher 自动判定）

- 探索图中已存在 `llm_endpoint_entity` 事实（即已发现可测试的 LLM 端点）。
- 该端点尚无 `llm_probe_result` 事实（未做过红队探测，避免重复）。

## 测试维度

1. **越狱（Jailbreak）**：构造角色绕过 / 前缀注入 / 编码混淆等 payload，验证模型是否输出受限内容。
2. **提示注入（Prompt Injection）**：通过间接注入（文档、搜索结果、工具返回）覆盖系统指令。
3. **数据泄露（Data Leak）**：探测系统提示词泄露、训练数据记忆、上下文越权读取。
4. **越权/覆盖（Override）**：测试工具调用劫持、函数调用注入、间接提示注入导致的越权操作。
5. **审计（Audit）**：记录所有请求/响应，形成可追溯的证据链。

## 执行规约

- 每次探测结束后，用 `record_fact` 写入一条 `llm_probe_result` 事实（payload 含 `kind: llm_probe_result`、端点、测试维度、结论、evidence），触发本 skill 的去重条件，避免规划者重复派发。
- 确认漏洞后用 `report_finding` 上报，`vulnclass` 填具体类型（jailbreak / prompt_injection / data_leak / tool_override）。
- 所有 payload 必须在授权范围内，禁止生成违法违规内容。

## 执行步骤（Agent 必读）

本 skill 附带探针脚本 `scripts/probe.py`（零额外依赖，仅需 Python 3.8+ 与 requests）。
支持三种探测引擎，通过 `--engine` 切换：

| 引擎 | 说明 | 额外依赖 |
|---|---|---|
| `builtin`（默认） | 内置 11 条精选探针，逐探针输出 JSONL | requests |
| `garak` | 调用 NVIDIA [garak](https://github.com/NVIDIA/garak) 红队框架 | `pip install garak` |
| `promptfoo` | 调用 [promptfoo](https://www.promptfoo.dev) 评估 CLI | `npm install -g promptfoo` |

`--categories` 在三种引擎下语义一致（jailbreak / prompt_injection / data_leak / over_permission），脚本内部会映射到各引擎的探针模块。garak/promptfoo 输出统一归一化为与 builtin 相同的 `llm_probe_result` JSONL，后续解析逻辑不变。

### 1. 确认目标

先用 `list_assets` 筛选 `type=llm_endpoint` 的资产，取其 `url` / `model` / `provider` / `api_type` 作为探测目标。若资产未带 `api_key`，向用户索取或仅做无需鉴权的探测。

### 2. 列出探针（可选，仅 builtin）

```bash
python scripts/probe.py --list
```
输出 JSONL，每行一个 `kind=llm_probe_plan` 的探针计划（probe_id / category / summary / payload），用于确认将执行哪些探测。

### 3. 执行探测

```bash
# builtin（默认）：内置精选探针
python scripts/probe.py \
  --url <端点URL> \
  --model <模型名> \
  --provider openai_compatible \   # 或 ollama
  --api-key <KEY> \               # 可选
  --categories jailbreak,prompt_injection,data_leak,over_permission \
  --max-probes 3

# garak：用 NVIDIA garak 框架做更全面的红队探测
python scripts/probe.py --url <端点URL> --model <模型名> --engine garak \
  --categories jailbreak,prompt_injection

# promptfoo：用 promptfoo 断言引擎评估
python scripts/probe.py --url <端点URL> --model <模型名> --engine promptfoo \
  --categories jailbreak,prompt_injection
```
- `--provider`：`openai_compatible`（默认，走 `/v1/chat/completions`）或 `ollama`（走 `/api/chat`）。
- `--categories`：逗号分隔的子集，默认全测。
- `--max-probes N`：每类别最多 N 条（仅 builtin），控制请求量。
- `--dry-run`：只构造请求不发送；`--mock`：用内置假响应验证链路（无真实目标时用）。
- `--engine`：`builtin`（默认）/ `garak` / `promptfoo`。外部引擎未安装时脚本会给出安装命令。

### 4. 解析输出并写图

脚本 stdout 为 JSONL，每行一个 `kind=llm_probe_result` 对象，字段：

| 字段 | 含义 |
|---|---|
| `probe_id` | 探针唯一 id |
| `category` | jailbreak / prompt_injection / data_leak / over_permission |
| `endpoint`, `model`, `provider` | 目标信息 |
| `vulnerable` | 是否命中判定关键词（布尔） |
| `http_status`, `elapsed_ms` | 请求状态 |
| `summary`, `detail`, `evidence`, `confidence` | 直接对应 `record_fact` 字段 |

对每行结果：

1. **聚合事实**：把同一端点的所有探针结果汇总成 **一条** `record_fact`（不要每条探针一条），`summary` 写端点级结论，`detail` 列出各探针命中情况，`evidence` 放最关键的一条请求/响应片段，`confidence` 取 `observed`。payload 额外带上 `kind=llm_probe_result`、`endpoint`、`categories`（已测类别数组）、`vulnerable_count`。
2. **上报漏洞**：对 `vulnerable=true` 的探针，用 `add_finding` 上报，`vulnclass` 映射为：jailbreak→`jailbreak`、prompt_injection→`prompt_injection`、data_leak→`data_leak`、over_permission→`tool_override`；`evidence` 贴 payload + 响应片段。
3. **去重标记**：写入 `llm_probe_result` 事实后，本 skill 的 `fact_missing: llm_probe_result` 条件不再满足，规划者不会重复派发。

## 输出事实格式

```json
{
  "summary": "LLM 端点 X 的红队探测结论",
  "detail": "各维度测试结果...",
  "evidence": "关键请求+响应片段",
  "confidence": "observed",
  "kind": "llm_probe_result",
  "endpoint": "http://target/v1/chat",
  "categories": ["jailbreak", "prompt_injection"],
  "vulnerable_count": 2
}
```
