from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import textwrap
from dataclasses import dataclass
from pathlib import Path


PRESET_SOLVERS = {
    "lean": ["web", "pwn"],
    "balanced": ["web", "pwn", "rev", "crypto"],
    "aggressive": ["web", "pwn", "rev", "crypto", "misc", "forensics"],
    "finals": ["web", "pwn", "rev", "crypto", "misc", "forensics", "general-1", "general-2"],
}

PLATFORM_RULES = {
    "gzctf": "优先通过站点/API/浏览器会话获取榜单、题目列表、题面、附件和 flag 提交入口；能用现成命令和工具就不要手搓大工程。",
}

REQUIRED_PERMISSION_MODE = "bypass_permissions"


@dataclass(frozen=True)
class LaunchSpec:
    name: str
    role: str
    affinity: str
    cwd: Path
    session_id: str
    prompt: str
    resume_prompt: str


def slugify(value: str) -> str:
    cleaned = []
    for char in value.strip().lower():
        if char.isalnum():
            cleaned.append(char)
        else:
            cleaned.append("-")
    slug = "".join(cleaned)
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug.strip("-") or "task"


def default_workspace() -> Path:
    return Path.cwd() / ".ctfagent-runtime"


def ensure_dirs(paths: list[Path]) -> None:
    for path in paths:
        path.mkdir(parents=True, exist_ok=True)


def shared_paths(workspace: Path) -> dict[str, Path]:
    return {
        "root": workspace,
        "shared": workspace / "shared",
        "board": workspace / "shared" / "board",
        "intake": workspace / "shared" / "intake",
        "coord": workspace / "shared" / "coord",
        "claims": workspace / "shared" / "claims",
        "flags": workspace / "shared" / "flags",
        "submissions": workspace / "shared" / "submissions",
        "core": workspace / "core",
        "challenges": workspace / "challenges",
    }


def common_block(args: argparse.Namespace, workspace: Path) -> str:
    extra = args.extra_context.strip()
    platform_rule = PLATFORM_RULES.get(args.platform, "优先复用现成工具，少写代码，多做验证。")
    lines = [
        f"比赛平台: {args.platform}",
        f"比赛名称: {args.ctf_name}",
        f"比赛地址: {args.base_url or '未提供，进入会话后先自行定位'}",
        f"主工作目录: {workspace}",
        f"共享目录: {workspace / 'shared'}",
        "总目标: 在实时比赛里尽可能拿高分，优先快题、稳题、可批量验证的题。",
        "总原则:",
        "1. 优先命令行、现成工具、浏览器、脚本片段、附件分析工具。",
        "2. 任何题都先判断投入产出比，避免硬刚低收益深坑。",
        "3. 所有关键结论写入共享目录，保证其他 agent 可接手。",
        "4. 找到 flag 候选后立即记录，并通知/交给 submitter 提交。",
        "5. 如缺少 CTF 常用工具链，先主动搜索是否已有现成工具/脚本可用；必要时可自行安装（例如 ctfskill），但要优先轻量、可复用、可快速验证的方案，并把安装/使用方法写入对应目录笔记。",
        f"平台特性: {platform_rule}",
    ]
    if extra:
        lines.append(f"额外上下文: {extra}")
    return "\n".join(lines)


def captain_prompt(args: argparse.Namespace, workspace: Path) -> str:
    return textwrap.dedent(
        f"""
        你是 CTF 总控 captain，只负责编排，不要自己陷入长时间手搓。

        {common_block(args, workspace)}

        你的职责:
        - 看榜、看题目列表、看已解/未解状态，决定先打什么。
        - 维护 {workspace / 'shared' / 'coord' / 'dispatch.json'}，给 solver 分题，避免重复劳动。
        - 维护 {workspace / 'shared' / 'coord' / 'priority.md'}，记录当前优先级、弃题原因、换人原因。
        - 发现某题长时间无进展时，立即降级或换人，不要死磕。
        - 发现高价值题或快题时，立即把 solver 资源集中过去。

        决策准则:
        - 先快后慢，先稳后险，先题面清晰/附件齐全/可快速试错的题。
        - 如果某类题出题风格明显适合某 solver，就优先给对应 solver。
        - 不要要求别人写大框架；优先让 solver 用最小脚本、现成 exploit、现成字典、现成工具链。

        输出要求:
        - 先给出“当前比赛态势摘要”。
        - 再给出“agent 分题表”。
        - 再给出“下一轮动作列表”。
        - 全程持续更新共享目录中的调度文件。
        """
    ).strip()


def board_prompt(args: argparse.Namespace, workspace: Path) -> str:
    return textwrap.dedent(
        f"""
        你是 scoreboard watcher，只负责盯榜和态势分析，不负责深度解题。

        {common_block(args, workspace)}

        你的职责:
        - 持续查看榜单、解题趋势、血题/热门题/高分题动态。
        - 把结论写入 {workspace / 'shared' / 'board' / 'scoreboard.md'}。
        - 把推荐优先级写入 {workspace / 'shared' / 'board' / 'targets.md'}。
        - 如果发现某题大量队伍秒解，立刻提示 captain 这是快题候选。
        - 如果发现某题分值上涨或解出人数极少，标记为高价值题，但也说明风险。

        分析口径:
        - 只做比赛态势、竞争对手动向、资源分配建议。
        - 不要长时间自己去解题。
        - 重点告诉 captain“该加人还是撤人”。
        """
    ).strip()


def intake_prompt(args: argparse.Namespace, workspace: Path) -> str:
    return textwrap.dedent(
        f"""
        你是 intake agent，负责看题、拉题面、下载附件、整理现场情报。

        {common_block(args, workspace)}

        你的职责:
        - 浏览题目列表，按分类整理所有题。
        - 下载/整理附件、题面、镜像地址、远程连接信息。
        - 每道题在 {workspace / 'challenges'} 下建立独立目录并整理材料。
        - 在 {workspace / 'shared' / 'intake' / 'challenge-index.md'} 维护总索引。
        - 为每题生成最短摘要：类型、附件、连接方式、可疑点、第一手思路。

        约束:
        - 你负责信息准备，不负责死磕解题。
        - 下载好附件后优先解压、file/strings/checksec/基础静态分析，给 solver 打底。
        - 所有整理结果都要落到共享目录，方便 solver 无缝接手。
        """
    ).strip()


def submitter_prompt(args: argparse.Namespace, workspace: Path) -> str:
    return textwrap.dedent(
        f"""
        你是 submitter，负责最后一公里：验证 flag 候选、提交 flag、记录结果。

        {common_block(args, workspace)}

        你的职责:
        - 关注 {workspace / 'shared' / 'flags'} 目录和各 challenge 目录中的 flag 候选。
        - 对候选 flag 做最小必要校验，避免明显错 flag 浪费机会。
        - 通过 gzctf 站点/API/浏览器会话提交 flag。
        - 在 {workspace / 'shared' / 'submissions' / 'submissions.ndjson'} 记录每次提交的时间、题目、flag、结果。
        - 若提交失败，区分“格式错 / 题目错 / 重复 / 平台异常”。

        工作原则:
        - 提交要快，但不能乱交一堆低置信度垃圾 flag。
        - 如果同一题有多个候选，按置信度排序逐个提交并记录。
        - 提交后立即把结果同步给 captain。
        """
    ).strip()


def solver_prompt(args: argparse.Namespace, workspace: Path, affinity: str) -> str:
    affinity_label = affinity.upper()
    extra_hint = {
        "web": "优先看路由、源码泄露、鉴权、模板注入、反序列化、文件读写、sql 注入、ssti、jwt、ssrf、rce。",
        "pwn": "优先 checksec、file、strings、运行样例、ida/ghidra、pwntools、glibc 版本、堆栈利用和 one_gadget。",
        "rev": "优先静态分析、控制流、加密/编码还原、关键常量、patch、符号执行和动态调试。",
        "crypto": "优先识别题型、搜集已知明文、参数关系、sage/python 最小验证，不要无边界爆破。",
        "misc": "优先文件格式、流量、隐写、二维码、压缩包、编码链、取证工具。",
        "forensics": "优先元数据、时间线、日志、内存/磁盘取证、浏览器痕迹、注册表/配置痕迹。",
    }.get(affinity, "优先判断题型并快速试错，必要时用最小脚本验证。")
    return textwrap.dedent(
        f"""
        你是 {affinity_label} solver，只负责拿题、解题、产出可提交 flag。

        {common_block(args, workspace)}

        你的职责:
        - 优先从 {workspace / 'shared' / 'coord' / 'dispatch.json'} 读取 captain 分配。
        - 如果暂时没有明确分配，则从 {workspace / 'shared' / 'intake' / 'challenge-index.md'} 中认领一个最适合你的题。
        - 把自己的认领结果写入 {workspace / 'shared' / 'claims' / (affinity + '.md')}。
        - 在对应 challenge 目录中完成分析、脚本、利用、笔记、flag 候选。
        - 一旦拿到 flag 候选，立即写入 challenge 目录和 {workspace / 'shared' / 'flags'}。

        解题准则:
        - 少写代码，优先现成命令、现成 exploit、现成字典、现成工具链。
        - 任何时候先做最快验证，不要一上来写大工程。
        - 卡住 15~20 分钟必须给 captain 一个明确状态：继续/换人/弃题。
        - 你的最终目标不是写漂亮笔记，而是稳定拿 flag。

        你的专项偏好:
        - {extra_hint}
        """
    ).strip()


def challenge_solver_prompt(args: argparse.Namespace, workspace: Path, affinity: str, challenge_name: str, challenge_dir: Path) -> str:
    return textwrap.dedent(
        f"""
        你是 {affinity} 专项 solver，现在只做一道题：{challenge_name}

        {common_block(args, workspace)}

        题目目录: {challenge_dir}
        当前任务:
        - 立即读取该目录下已有题面、附件、笔记、脚本。
        - 只围绕这道题推进，直到拿到 flag、明确卡点、或判断应弃题。
        - 所有关键发现写入 {challenge_dir / 'notes.md'}。
        - 有 flag 候选立刻写入 {challenge_dir / 'flag.txt'} 和 {workspace / 'shared' / 'flags'}。

        约束:
        - 不要跑偏去看别的题。
        - 少写代码，优先最小验证、现成利用链、现成工具。
        - 如果无法突破，必须给出具体阻塞点和下一步建议，而不是泛泛而谈。
        """
    ).strip()


def resume_prompt(spec: LaunchSpec) -> str:
    role_specific = {
        "captain": "继续当前 CTF 总控任务。重新查看共享目录、榜单和题目分配，主动调整 dispatch，继续推进，不要等待用户。",
        "board": "继续盯榜和比赛态势分析。重新查看榜单变化并更新共享目录，给 captain 新的资源分配建议，不要等待用户。",
        "intake": "继续看题、拉题面、下载附件、整理 challenge 索引。优先补齐新增题目和未整理材料，不要等待用户。",
        "submitter": "继续检查新的 flag 候选并提交。若暂无 flag，则继续巡检共享目录并等待可提交目标，但不要退出。",
        "solver": "继续当前解题任务。先检查 captain 分配和 challenge 目录，再主动推进分析、验证和拿 flag，不要等待用户。",
        "challenge-solver": "继续这道题的专项解题任务。读取已有笔记和附件，继续推进直到拿到 flag 或产出明确阻塞点，不要等待用户。",
    }
    return role_specific.get(spec.role, "继续当前任务，不要等待用户，主动检查共享目录并持续推进。")


def build_spec(name: str, role: str, affinity: str, cwd: Path, prompt: str) -> LaunchSpec:
    session_id = f"ctfagent-{slugify(name)}"
    base = LaunchSpec(name=name, role=role, affinity=affinity, cwd=cwd, session_id=session_id, prompt=prompt, resume_prompt="")
    return LaunchSpec(
        name=base.name,
        role=base.role,
        affinity=base.affinity,
        cwd=base.cwd,
        session_id=base.session_id,
        prompt=base.prompt,
        resume_prompt=resume_prompt(base),
    )


def match_specs(args: argparse.Namespace, workspace: Path) -> list[LaunchSpec]:
    paths = shared_paths(workspace)
    specs = [
        build_spec("captain", "captain", "captain", paths["core"] / "captain", captain_prompt(args, workspace)),
        build_spec("board", "board", "board", paths["core"] / "board", board_prompt(args, workspace)),
        build_spec("intake", "intake", "intake", paths["core"] / "intake", intake_prompt(args, workspace)),
        build_spec("submitter", "submitter", "submitter", paths["core"] / "submitter", submitter_prompt(args, workspace)),
    ]
    for affinity in PRESET_SOLVERS[args.preset]:
        specs.append(
            build_spec(
                f"solver-{affinity}",
                "solver",
                affinity,
                paths["core"] / f"solver-{affinity}",
                solver_prompt(args, workspace, affinity),
            )
        )
    return specs


def challenge_specs(args: argparse.Namespace, workspace: Path) -> list[LaunchSpec]:
    challenge_slug = slugify(args.challenge_name)
    challenge_dir = shared_paths(workspace)["challenges"] / challenge_slug
    specs = []
    for index in range(1, args.copies + 1):
        name = f"{challenge_slug}-{args.category}-{index}"
        cwd = challenge_dir / f"solver-{args.category}-{index}"
        specs.append(
            build_spec(
                name,
                "challenge-solver",
                args.category,
                cwd,
                challenge_solver_prompt(args, workspace, args.category, args.challenge_name, challenge_dir),
            )
        )
    return specs


def quote_command(parts: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in parts)


def coco_command(
    spec: LaunchSpec,
    args: argparse.Namespace,
    interactive: bool,
    prompt: str | None = None,
    resume: bool = False,
) -> list[str]:
    selected_prompt = spec.prompt if prompt is None else prompt
    cmd = [args.agent_bin]
    if interactive:
        cmd.append(selected_prompt)
    else:
        cmd.extend(["-p", selected_prompt, "--output-format", "stream-json"])
    cmd.extend(["-c", f"permission_mode={REQUIRED_PERMISSION_MODE}"])
    if resume:
        cmd.extend(["--resume", spec.session_id])
    else:
        cmd.extend(["--session-id", spec.session_id])
    if args.query_timeout:
        cmd.extend(["--query-timeout", args.query_timeout])
    if args.bash_timeout:
        cmd.extend(["--bash-tool-timeout", args.bash_timeout])
    return cmd


def print_specs(specs: list[LaunchSpec]) -> None:
    for spec in specs:
        print(f"[{spec.name}] role={spec.role} affinity={spec.affinity}")
        print(f"  cwd: {spec.cwd}")
        print(f"  session: {spec.session_id}")
        print("  prompt:")
        print(textwrap.indent(spec.prompt, "    "))
        print("  resume_prompt:")
        print(textwrap.indent(spec.resume_prompt, "    "))
        print()


def continuous_shell_command(spec: LaunchSpec, args: argparse.Namespace) -> str:
    first_cmd = quote_command(coco_command(spec, args, interactive=False))
    resume_cmd = quote_command(coco_command(spec, args, interactive=False, prompt=spec.resume_prompt, resume=True))
    sleep_seconds = max(args.loop_interval, 1)
    lines = [
        "first_round=1",
        "while true; do",
        '  if [ "$first_round" -eq 1 ]; then',
        f"    {first_cmd}",
        "    first_round=0",
        "  else",
        f"    {resume_cmd}",
        "  fi",
        '  status=$?',
        '  printf "\\n[ctfagent-supervisor] agent=%s exit=%s sleep=%ss\\n" ' + shlex.quote(spec.name) + ' "$status" ' + shlex.quote(str(sleep_seconds)),
        f"  sleep {sleep_seconds}",
        "done",
    ]
    return "\n".join(lines)


def launch_subprocess(spec: LaunchSpec, args: argparse.Namespace) -> None:
    ensure_dirs([spec.cwd])
    stdout_path = spec.cwd / "agent.stdout.log"
    stderr_path = spec.cwd / "agent.stderr.log"
    if args.continuous:
        cmd = ["/bin/sh", "-lc", continuous_shell_command(spec, args)]
    else:
        cmd = coco_command(spec, args, interactive=False)
    with stdout_path.open("a", encoding="utf-8") as stdout, stderr_path.open("a", encoding="utf-8") as stderr:
        subprocess.Popen(cmd, cwd=spec.cwd, stdout=stdout, stderr=stderr)


def launch_terminal(spec: LaunchSpec, args: argparse.Namespace) -> None:
    ensure_dirs([spec.cwd])
    if args.continuous:
        shell_body = continuous_shell_command(spec, args)
    else:
        shell_body = quote_command(coco_command(spec, args, interactive=True))
    script = f"cd {shlex.quote(str(spec.cwd))} && {shell_body}"
    subprocess.Popen(
        [
            "osascript",
            "-e",
            f"tell application \"Terminal\" to do script {json.dumps(script)}",
            "-e",
            'tell application "Terminal" to activate',
        ]
    )


def prepare_workspace(workspace: Path) -> None:
    paths = shared_paths(workspace)
    ensure_dirs(list(paths.values()))


def handle_roster(args: argparse.Namespace) -> int:
    workspace = args.workspace.resolve()
    specs = match_specs(args, workspace)
    total = len(specs)
    print(f"preset={args.preset} total_agents={total}")
    print(f"workspace={workspace}")
    print("目录布局:")
    print(f"  shared: {workspace / 'shared'}")
    print(f"  core: {workspace / 'core'}")
    print(f"  challenges: {workspace / 'challenges'}")
    print()
    if args.show_prompts:
        print_specs(specs)
        return 0
    for spec in specs:
        print(f"- {spec.name:16} -> {spec.cwd}")
    return 0


def handle_launch_match(args: argparse.Namespace) -> int:
    workspace = args.workspace.resolve()
    prepare_workspace(workspace)
    specs = match_specs(args, workspace)
    if args.dry_run or args.executor == "print":
        for spec in specs:
            mode = "continuous" if args.continuous else ("interactive" if args.executor == "terminal" else "non-interactive")
            print(f"[{spec.name}] cwd={spec.cwd} mode={mode}")
            if args.continuous:
                print(continuous_shell_command(spec, args))
            else:
                cmd = coco_command(spec, args, interactive=args.executor == "terminal")
                print(quote_command(cmd))
            print()
        return 0
    launcher = launch_terminal if args.executor == "terminal" else launch_subprocess
    for spec in specs:
        launcher(spec, args)
        print(f"launched {spec.name} -> {spec.cwd}")
    return 0


def handle_launch_challenge(args: argparse.Namespace) -> int:
    workspace = args.workspace.resolve()
    prepare_workspace(workspace)
    specs = challenge_specs(args, workspace)
    if args.dry_run or args.executor == "print":
        for spec in specs:
            mode = "continuous" if args.continuous else ("interactive" if args.executor == "terminal" else "non-interactive")
            print(f"[{spec.name}] cwd={spec.cwd} mode={mode}")
            if args.continuous:
                print(continuous_shell_command(spec, args))
            else:
                cmd = coco_command(spec, args, interactive=args.executor == "terminal")
                print(quote_command(cmd))
            print()
        return 0
    launcher = launch_terminal if args.executor == "terminal" else launch_subprocess
    for spec in specs:
        launcher(spec, args)
        print(f"launched {spec.name} -> {spec.cwd}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Minimal multi-agent CTF orchestrator for coco/traecli")
    parser.add_argument("--platform", default="gzctf", help="比赛平台，默认 gzctf")
    parser.add_argument("--ctf-name", default="unnamed-ctf", help="比赛名称")
    parser.add_argument("--base-url", default="", help="比赛首页或平台地址")
    parser.add_argument("--workspace", type=Path, default=default_workspace(), help="CTF agent 运行目录")
    parser.add_argument("--agent-bin", default=os.environ.get("CTFAGENT_BIN", "coco"), help="agent 启动命令，默认 coco")
    parser.add_argument("--query-timeout", default="20m", help="coco 单次 query 超时")
    parser.add_argument("--bash-timeout", default="10m", help="coco bash tool 超时")
    parser.add_argument("--loop-interval", type=int, default=8, help="continuous 模式下每轮重启前 sleep 秒数")
    parser.add_argument("--extra-context", default="", help="追加到所有 agent prompt 的额外上下文")

    subparsers = parser.add_subparsers(dest="command", required=True)

    roster = subparsers.add_parser("roster", help="查看推荐的 agent 编排")
    roster.add_argument("--preset", choices=sorted(PRESET_SOLVERS), default="balanced")
    roster.add_argument("--show-prompts", action="store_true", help="显示完整 prompt")
    roster.set_defaults(func=handle_roster)

    launch_match = subparsers.add_parser("launch-match", help="启动整场比赛编排")
    launch_match.add_argument("--preset", choices=sorted(PRESET_SOLVERS), default="balanced")
    launch_match.add_argument("--executor", choices=["print", "subprocess", "terminal"], default="print")
    launch_match.set_defaults(continuous=True)
    launch_match.add_argument("--once", dest="continuous", action="store_false", help="只跑一轮，不做持续 supervisor")
    launch_match.add_argument("--dry-run", action="store_true")
    launch_match.set_defaults(func=handle_launch_match)

    launch_challenge = subparsers.add_parser("launch-challenge", help="围绕单题启动多个 solver")
    launch_challenge.add_argument("--challenge-name", required=True, help="题目名称")
    launch_challenge.add_argument("--category", default="web", help="题目类别，如 web/pwn/rev/crypto/misc")
    launch_challenge.add_argument("--copies", type=int, default=2, help="为单题开多少个 solver")
    launch_challenge.add_argument("--executor", choices=["print", "subprocess", "terminal"], default="print")
    launch_challenge.set_defaults(continuous=True)
    launch_challenge.add_argument("--once", dest="continuous", action="store_false", help="只跑一轮，不做持续 supervisor")
    launch_challenge.add_argument("--dry-run", action="store_true")
    launch_challenge.set_defaults(func=handle_launch_challenge)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
