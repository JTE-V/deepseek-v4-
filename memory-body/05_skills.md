# 05 技能锚 — 宿主该输出的形态

技能锚定义宿主在不同任务下"不乱"的输出结构。每个技能 = 一种任务 + 输出 JSON schema + 纪律。

## S1 情报结构化（外部情报/任意文本 → 结构化 JSON）

```
{ "cve": null, "unrelated": false, "affected_component": "...",
  "affected_versions": ["..."], "cwe": null, "cvss": null,
  "public_exploit": "unknown", "attack_vector": null,
  "summary": "...", "evidence": ["原文逐字片段"] }
```
纪律：原文没有的字段一律 null/unknown；evidence 逐字；无关输入只报 unrelated。

## S2 因素提取（严重性判断材料 → 因素 JSON）

```
{ "exploitable": null, "public_exploit": null, "internet_facing": null,
  "auth_required": null, "attack_complexity": null,
  "impact": {"confidentiality": null, "integrity": null, "availability": null},
  "reasoning": ["每条判断的理由"] }
```
纪律：只输出因素与理由，不输出等级（等级由规则计算）。

## S3 内部分析（扫描结果 + 资产清单 → 匹配 JSON）

```
{ "findings": [{"id": "...", "package_or_component": "...",
    "installed_version": "...", "vulnerable_range": "...",
    "cve": "...", "matched_assets": [...], "exposure": "..."}],
  "unmatched": [...], "notes": "..." }
```
纪律：只匹配清单里真实存在的对象；匹配不上进 unmatched，禁止猜测。

## S4 好奇心（给事件 → 搜原因/概念；不给事件 → 缺口探测）

```
{ "event": "...或null",
  "curiosity": { "causes": [{"hypothesis","basis","status"}],
                 "concepts": [{"concept","linked_to","novelty"}],
                 "gaps": [{"gap","why_needed","action"}] },
  "honesty": {"speculation_marked": true, "facts_count": 0, "speculations_count": 0} }
```
纪律：推测标注三档（confirmed/inferred/speculative）；speculative 措辞带不确定标记；
无事件只输出 gaps；缺口三要素齐全；不下结论。

## 通用输出纪律（所有技能）

- 只输出 JSON，无其他文字
- 不输出等级/告警/最终判定（红线 1）
- evidence 逐字引用输入（红线 4）
