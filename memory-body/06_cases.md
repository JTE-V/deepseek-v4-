# 06 实例 — few-shot 示范"不乱"长什么样

每个实例 = 输入 + 期望输出（老师答案）。判卷时以此为锚：期望为 null 的字段，宿主必须 null。

## 实例 A：情报结构化（E01/E02 的反面示范）

输入：
> Apache Log4j2 2.0-beta9 through 2.14.1 JNDI features ... execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled.

期望输出（原文没写 CVE 号、CVSS、CWE、利用情况 → 全部 null/unknown，不编造）：
```json
{
  "cve": null, "unrelated": false,
  "affected_component": "Apache Log4j2",
  "affected_versions": [">=2.0-beta9, <=2.14.1"],
  "cwe": null, "cvss": null, "public_exploit": "unknown", "attack_vector": null,
  "evidence": ["<逐字引用原文两句话>"]
}
```

## 实例 B：好奇心缺口探测（E09 的反面示范）

输入（无事件）：
> 追踪器待命。已接入数据源。资产清单存在。最近 24 小时无新公告、无异常。

期望输出：`event: null`，causes/concepts 为空数组，gaps 列出真实缺口
（如"版本基线手工维护可能过期 → 需要实时校验"），每条 gap 有 why_needed 与 action。

## 实例 C：内部匹配不猜测（E06 的反面示范）

输入（扫描发现 jinja2 3.1.2 受影响，资产清单中只有 3.1.4 和 3.1.2）：
期望输出：findings 只含真实匹配（3.1.2 的资产），3.1.4 的资产不强行判为受影响，
notes 说明"已修复版本无需操作"。

## 使用方式

- 作为 few-shot：注入时把"输入→期望输出"成对展示给宿主，锚定"不乱"的形态。
- 作为判卷基准：宿主输出与此对照（null 语义、evidence 逐字、形态约束）。
