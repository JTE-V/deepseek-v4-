#!/usr/bin/env python3
"""记忆体注入器 — 把 memory-body/ 搭载到任意 OpenAI 兼容宿主，输出自动判卷。

记忆体是纯文本纪律（memory-body/），本工具是它的可执行注入器，位于 tools/，
不污染记忆体的纯文本性质，不依赖任何具体项目。

用法:
  python inject.py <input_text>                    # 直接给文本，默认技能 S1
  python inject.py <input_text> --skill S4          # 指定技能锚（S1–S4）
  python inject.py --file input.txt --skill S3      # 从文件读输入
  python inject.py --file in.txt --expected exp.json  # 带期望输出做严格判卷
  python inject.py --self-test                      # 自检（不调 API）

宿主切换（任意 OpenAI 兼容端点）:
  --model    deepseek-v4-flash | deepseek-chat | 其他
  --endpoint https://api.deepseek.com/chat/completions | 其他兼容端点
  --env-key  DEEPSEEK_API_KEY（默认）| 其他环境变量名

红线 2: 密钥只走环境变量，本文件/命令不含密钥。
流程: 01+02 → system(纪律) | 05 技能锚 + 06 实例 → few-shot | 宿主输出 → 02_verify 判卷 → 报告
"""

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

HERE = Path(__file__).resolve().parent
MB = HERE.parent.parent / "memory-body"  # tools/memory-injector/ → memory-body/

# ============ 读记忆体 ============


def load_memory() -> dict[str, str]:
    """读取 memory-body 六份文本。缺失文件 → 明确报错（红线 3：不静默）。"""
    names = {
        "redlines": "01_redlines.md",
        "verify": "02_verify.md",
        "errors": "03_errors.md",
        "memory": "04_memory.md",
        "skills": "05_skills.md",
        "cases": "06_cases.md",
    }
    out: dict[str, str] = {}
    for key, fname in names.items():
        p = MB / fname
        if not p.exists():
            raise FileNotFoundError(f"[inject] 记忆体缺文件: {p}（记忆体不完整，拒绝注入）")
        out[key] = p.read_text(encoding="utf-8")
    return out


def build_system(mem: dict[str, str]) -> str:
    """system prompt：红线 + 判卷标准 + 错题本要点 + 记忆要点（纪律层）。"""
    return (
        "你是搭载记忆体的输出维护体。以下纪律是最高约束，违反任何一条即判卷 FAIL：\n\n"
        "# 红线\n" + mem["redlines"]
        + "\n\n# 判卷标准（你的输出将按此判卷）\n" + mem["verify"]
        + "\n\n# 错题本（常见错误，避免重犯）\n" + mem["errors"]
        + "\n\n# 记忆（已沉淀的教训）\n" + mem["memory"]
    )


def parse_skill(skill: str) -> tuple[str, str]:
    """从 05_skills.md 提取技能锚块。返回 (标题, 内容)。"""
    m = re.search(r"(## S\d+[^\n]*\n.*?)(?=\n## S\d+|\Z)", skill, re.S)
    return ("S 技能锚", m.group(1).strip() if m else skill.strip())


def build_fewshot(mem: dict[str, str]) -> list[dict]:
    """few-shot：把 06_cases.md 的实例块转成 user/assistant 消息对（示范"不乱"）。"""
    cases_text = mem["cases"]
    blocks = re.split(r"\n## 实例[^\n]*\n", cases_text)[1:]
    messages: list[dict] = []
    for b in blocks:
        # 小节标题允许带括号说明，如"输入："、"期望输出（…）："
        in_m = re.search(r"输入[^：:]*[：:]\s*(.*?)(?=\n期望输出|\Z)", b, re.S)
        out_m = re.search(r"期望输出[^：:]*[：:]\s*(.*?)\s*\Z", b, re.S)
        if in_m and out_m:
            user = in_m.group(1).strip()
            assistant = out_m.group(1).strip()
            # 期望输出若为 json 围栏块则剥掉围栏
            m = re.search(r"```(?:json)?\s*(.*?)\s*```", assistant, re.S)
            if m:
                assistant = m.group(1)
            messages.append({"role": "user", "content": user})
            messages.append({"role": "assistant", "content": assistant})
    return messages


# ============ 判卷器（02_verify.md 的可执行版） ============

SPEC_MARKERS = ("可能", "推测", "待验证", "或许", "疑似", "probably", "possibly", "likely", "unverified")
NULL_OK = (None, "", "unknown", "null")


def norm(s: str) -> str:
    return re.sub(r"\s+", " ", str(s)).strip()


def verify_output(output: dict, input_text: str, expected: dict | None, problems: list[str]) -> None:
    """按 02_verify.md 判卷。problems 就地收集。"""
    case = "[verify]"
    # 2.1 结构（有 expected 时）
    if expected is not None:
        for k, v in expected.items():
            if k not in output:
                problems.append(f"{case} 缺少字段 {k} (期望: {v!r})")
            elif isinstance(v, list) and not isinstance(output[k], list):
                problems.append(f"{case} 字段 {k} 类型应为 list, 实际 {type(output[k]).__name__}")
    # 2.2 null 语义
    if expected is not None:
        for k, v in expected.items():
            if v is None and output.get(k) not in NULL_OK:
                problems.append(f"{case} 字段 {k} 期望 null(原文没有), 实际 {output.get(k)!r} — E01 背景知识污染")
    # 2.4 evidence 逐字红线
    in_norm = norm(input_text)
    for ev in output.get("evidence", []) if isinstance(output.get("evidence"), list) else []:
        if norm(ev) not in in_norm:
            problems.append(f"{case} evidence 不是原文逐字引用: {ev!r} — E02")
    # 2.5 越权检查（输出不得下等级/告警结论）
    for key in ("severity", "alert", "level", "priority", "decision"):
        if key in output and output[key] not in (None, ""):
            problems.append(f"{case} 输出含 {key}（越权定级）— E03")
    # 2.6 推测标注
    for i, h in enumerate(output.get("curiosity", {}).get("causes", [])
                          if isinstance(output.get("curiosity"), dict) else []):
        if isinstance(h, dict) and h.get("status") == "speculative":
            if not any(m in norm(h.get("hypothesis", "")) for m in SPEC_MARKERS):
                problems.append(f"{case} causes[{i}] speculative 但措辞像事实: {h.get('hypothesis')!r} — E08")
    # 2.7 形态约束（无事件 → 只输出 gaps）
    if output.get("event") in (None, "", "null"):
        c = output.get("curiosity", {})
        if isinstance(c, dict) and (c.get("causes") or c.get("concepts")):
            problems.append(f"{case} 无事件却输出 causes/concepts — E09 无纪律发散")
        for i, g in enumerate(c.get("gaps", []) if isinstance(c, dict) else []):
            if not isinstance(g, dict):
                problems.append(f"{case} gaps[{i}] 应为对象")
                continue
            for field in ("gap", "why_needed", "action"):
                if not norm(g.get(field, "")):
                    problems.append(f"{case} gaps[{i}].{field} 为空 — E09 缺口必须可行动")
    # 2.8 诚实自证
    h = output.get("honesty")
    if isinstance(h, dict) and h.get("speculation_marked") is not True:
        problems.append(f"{case} honesty.speculation_marked 必须为 true")


# ============ 宿主调用 ============

def call_host(system: str, fewshot: list[dict], user_prompt: str,
              model: str, endpoint: str, env_key: str) -> tuple[dict, dict]:
    key = os.environ.get(env_key)
    if not key:
        raise RuntimeError(f"[inject] 缺环境变量 {env_key}（红线 2：密钥只走环境变量）")
    messages = [{"role": "system", "content": system}]
    messages.extend(fewshot)
    messages.append({"role": "user", "content": user_prompt})
    body = {
        "model": model,
        "messages": messages,
        "temperature": 0.1,
        "thinking": {"type": "disabled"},  # v4 系列默认开 thinking，非推理任务关闭省流量
        "response_format": {"type": "json_object"},
    }
    req = urllib.request.Request(
        endpoint,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}"},
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    content = data["choices"][0]["message"]["content"].strip()
    m = re.search(r"```(?:json)?\s*(.*?)\s*```", content, re.S)
    if m:
        content = m.group(1)
    result = json.loads(content)
    usage = data.get("usage", {})
    meta = {
        "provider": "openai-compatible",
        "model": model,
        "tokens": {k: usage.get(k) for k in ("prompt_tokens", "completion_tokens", "total_tokens") if k in usage},
    }
    if not isinstance(result.get("meta"), dict):
        result["meta"] = {}
    result["meta"].update(meta)
    return result, meta


# ============ 自检（不调 API） ============

def self_test() -> None:
    print("== 记忆体注入器自检 ==")
    mem = load_memory()
    print(f"✓ 读入记忆体 {len(mem)} 份文本: {', '.join(mem)}")
    system = build_system(mem)
    assert "五条红线" in system or "红线" in system
    assert "判卷标准" in system
    print(f"✓ system prompt 组装 ({len(system)} 字符)，含红线与判卷标准")
    fs = build_fewshot(mem)
    print(f"✓ few-shot 消息对: {len(fs)} 条（{'user/assistant 成对' if len(fs) % 2 == 0 and fs else '为空，需补实例'}）")
    # 判卷器行为自检
    input_text = "Apache Log4j2 2.0-beta9 through 2.14.1 存在 JNDI 注入风险。"
    bad = {
        "cve": "CVE-2021-44228",  # E01: 原文没有
        "evidence": ["改写过的证据"],  # E02: 非逐字
        "severity": "critical",  # E03: 越权
        "curiosity": {"causes": [{"hypothesis": "这一定被利用了", "status": "speculative"}]},  # E08
    }
    problems: list[str] = []
    verify_output(bad, input_text, {"cve": None, "unrelated": False}, problems)
    assert len(problems) >= 4, f"判卷器应至少抓 4 个问题, 实际 {len(problems)}: {problems}"
    print(f"✓ 判卷器命中 {len(problems)} 个错误:")
    for p in problems:
        print("   " + p)
    good = {"cve": None, "unrelated": False, "evidence": ["Apache Log4j2 2.0-beta9 through 2.14.1 存在 JNDI 注入风险。"]}
    problems2: list[str] = []
    verify_output(good, input_text, {"cve": None, "unrelated": False}, problems2)
    assert not problems2, f"好输出不应有错: {problems2}"
    print("✓ 好输出 0 错误")
    print("== 自检 PASS ==")


# ============ 主入口 ============

def main() -> None:
    parser = argparse.ArgumentParser(description="记忆体注入器：搭载 memory-body 到任意 OpenAI 兼容宿主")
    parser.add_argument("input", nargs="?", help="输入文本（或用 --file）")
    parser.add_argument("--file", help="从文件读输入")
    parser.add_argument("--skill", default="S1", help="技能锚：S1–S4（默认 S1）")
    parser.add_argument("--model", default="deepseek-v4-flash")
    parser.add_argument("--endpoint", default="https://api.deepseek.com/chat/completions")
    parser.add_argument("--env-key", default="DEEPSEEK_API_KEY")
    parser.add_argument("--expected", help="期望输出 JSON 文件（严格判卷）")
    parser.add_argument("--self-test", action="store_true", help="自检（不调 API）")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return

    if args.input is None and args.file is None:
        parser.error("需提供输入文本（位置参数）或 --file")

    input_text = args.input if args.input is not None else Path(args.file).read_text(encoding="utf-8").strip()
    mem = load_memory()
    system = build_system(mem)
    fewshot = build_fewshot(mem)
    skill_block = parse_skill(mem["skills"])[1] if args.skill else ""
    user_prompt = f"任务技能锚：\n{skill_block}\n\n输入：\n{input_text}\n\n请按技能锚输出 JSON。"

    expected = None
    if args.expected:
        expected = json.loads(Path(args.expected).read_text(encoding="utf-8"))

    result, meta = call_host(system, fewshot, user_prompt, args.model, args.endpoint, args.env_key)
    out = Path("inject_output.json")
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    problems: list[str] = []
    verify_output(result, input_text, expected, problems)
    print(f"宿主: {meta['provider']} | model: {meta['model']} | tokens: {meta.get('tokens')}")
    if problems:
        print(f"✗ FAIL — 判卷发现 {len(problems)} 个问题:")
        for p in problems:
            print("   " + p)
        print("修正建议: 按 memory-body/03_errors.md 归因（E-code）后重试或修正宿主。")
        print("输出已保留: inject_output.json（红线 3：错误可见可追溯，不静默）")
        sys.exit(1)
    print("✓ PASS — 输出通过记忆体判卷，已写入 inject_output.json")


if __name__ == "__main__":
    main()
