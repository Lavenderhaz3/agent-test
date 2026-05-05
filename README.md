# CodeSentinel

基于 OpenClaw + Claude + GPT 系列的多模型协作智能体，专为自动化代码审查与安全保障而构建。

CodeSentinel 协调三大 AI 引擎协同工作：Claude 负责静态代码扫描与漏洞检测（覆盖 OWASP Top 10），GPT 生成详细的 PR 评审与优化建议，OpenClaw 驱动单元测试自动执行及失败分析。所有结果统一聚合为结构化报告，通过 Slack、Teams、飞书、钉钉一键推送至团队协作工具，原生支持中、英、日、韩等多语言团队协作。让代码审查从人工负担变为自动化流水线。

## 安装

```bash
pip install -e .
```

需要 Python 3.9+（推荐 3.11+）。

## 使用

```bash
# 完整工作流
codesentinel run --repo /path/to/repo --diff pr.diff --notify

# 仅安全扫描
codesentinel scan --repo /path/to/repo

# 仅 PR 审查
codesentinel review --diff pr.diff

# 仅运行测试
codesentinel test --repo /path/to/repo

# 查看配置
codesentinel show-config
```

## 环境变量

| 变量 | 说明 |
|------|------|
| `ANTHROPIC_API_KEY` | Claude API 密钥 |
| `OPENAI_API_KEY` | GPT API 密钥 |
| `SLACK_WEBHOOK_URL` | Slack 通知 Webhook |
| `TEAMS_WEBHOOK_URL` | Teams 通知 Webhook |
| `FEISHU_WEBHOOK_URL` | 飞书通知 Webhook |
| `DINGTALK_WEBHOOK_URL` | 钉钉通知 Webhook |

## 架构

```
cli ──► orchestrator ──┬── scanner   (Claude → 漏洞检测)
                        ├── reviewer  (GPT → PR 评审)
                        ├── runner    (OpenClaw → 测试执行)
                        ├── aggregator (报告聚合)
                        └── notifier  (多平台推送)
```

## License

MIT
