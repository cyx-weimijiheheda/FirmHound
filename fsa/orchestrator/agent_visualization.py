"""Render the bounded agent trace as a self-contained, offline HTML view."""

# ruff: noqa: E501 -- embedded CSS/JavaScript is intentionally self-contained.

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_ACTION_LABELS = {
    "recover_call_chain": "恢复调用链",
    "cross_check_imports_strings": "核对导入与字符串",
    "check_handler_startup": "核对入口启动路径",
    "cross_check_evidence_store": "交叉检查证据",
    "verify_auth_hint": "核验认证要求",
    "enrich_from_recovered_handlers": "映射真实处理函数",
    "qemu_load_check": "QEMU 加载检查",
    "klee_feasibility": "KLEE 可达性检查",
}

_FACT_LABELS = {
    "call_chain_reachable": "调用链可达",
    "source_sink_cross_checked": "Source/Sink 已核对",
    "handler_startup_checked": "入口启动关系已核对",
    "contradiction_checked": "反证已核对",
    "auth_known": "认证要求已明确",
    "entry_mapped": "入口已映射",
    "dynamic_load_checked": "动态加载已检查",
    "symex_feasibility_checked": "符号执行已检查",
}

_STATUS_LABELS = {
    "ok": "完成",
    "degraded": "有限完成",
    "partial": "部分完成",
    "failed": "失败",
    "skipped": "跳过",
    "stalled": "停滞",
    "running": "执行中",
}


def _safe_json(value: Any) -> str:
    """Serialize trace data safely inside a script element."""
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def render_agent_visualization(trace: dict[str, Any]) -> str:
    """Return a responsive graph view with the selected path and legal branches."""
    labels = {"actions": _ACTION_LABELS, "facts": _FACT_LABELS, "statuses": _STATUS_LABELS}
    payload = _safe_json({"trace": trace, "labels": labels})
    return r"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light">
<title>FirmHound Agent 执行路径</title>
<style>
:root{font-family:Inter,"Noto Sans SC","Microsoft YaHei",system-ui,sans-serif;color:#172033;background:#f3f6fb;font-synthesis:none;text-rendering:optimizeLegibility;--ink:#172033;--muted:#64748b;--line:#dbe3ef;--blue:#2563eb;--purple:#7c3aed;--teal:#0f766e;--green:#15803d;--amber:#b45309;--red:#b91c1c;--gray:#64748b}
*{box-sizing:border-box}body{margin:0}button,select,input{font:inherit}.shell{max-width:1440px;margin:auto;padding:32px clamp(16px,4vw,52px) 64px}.eyebrow{font-size:12px;font-weight:750;letter-spacing:.12em;text-transform:uppercase;color:#2563eb}.title-row{display:flex;align-items:flex-start;justify-content:space-between;gap:20px;margin:8px 0 22px}.title-row h1{font-size:clamp(25px,4vw,38px);line-height:1.15;margin:0;letter-spacing:-.035em}.subtitle{margin:10px 0 0;color:var(--muted);max-width:760px}.run-chip{border:1px solid var(--line);background:#fff;border-radius:999px;padding:9px 13px;color:#334155;font-size:13px;white-space:nowrap}.run-chip b{color:var(--blue)}.stats{display:grid;grid-template-columns:repeat(5,minmax(120px,1fr));gap:12px;margin:24px 0}.stat{background:#fff;border:1px solid var(--line);border-radius:14px;padding:15px 17px;box-shadow:0 2px 8px #15233a08}.stat span{display:block;color:var(--muted);font-size:12px}.stat strong{display:block;margin-top:7px;font-size:22px;letter-spacing:-.03em}.toolbar{display:flex;flex-wrap:wrap;align-items:center;gap:10px;background:#fff;border:1px solid var(--line);border-radius:14px;padding:12px;margin:20px 0}.toolbar label{color:var(--muted);font-size:12px;font-weight:700}.toolbar select,.toolbar input{border:1px solid var(--line);border-radius:9px;background:#fff;color:var(--ink);padding:9px 11px;outline:none}.toolbar input{min-width:210px;flex:1}.toolbar select:focus,.toolbar input:focus{border-color:#60a5fa;box-shadow:0 0 0 3px #dbeafe}.legend{display:flex;flex-wrap:wrap;gap:8px 15px;margin:0 0 17px;color:var(--muted);font-size:12px}.legend span{display:inline-flex;align-items:center;gap:6px}.dot{height:9px;width:9px;border-radius:50%;background:var(--gray)}.dot.rule{background:var(--blue)}.dot.model{background:var(--purple)}.dot.success{background:var(--green)}.dot.warn{background:#d97706}.dot.fail{background:var(--red)}.dot.alt{background:#94a3b8}.section-title{font-size:17px;margin:30px 0 13px;letter-spacing:-.02em}.timeline{position:relative;display:grid;gap:13px}.timeline:before{content:"";position:absolute;left:21px;top:22px;bottom:25px;width:2px;background:linear-gradient(#93c5fd,#cbd5e1 70%,transparent)}.step{position:relative;display:grid;grid-template-columns:44px minmax(0,1fr);gap:12px;align-items:start}.step-index{z-index:1;width:44px;height:44px;border-radius:14px;background:#eaf1ff;border:1px solid #bfdbfe;color:#1d4ed8;display:grid;place-items:center;font-size:12px;font-weight:800}.step-card{border:1px solid var(--line);border-left:4px solid var(--blue);border-radius:14px;background:#fff;padding:15px 17px;box-shadow:0 3px 10px #15233a08;cursor:pointer;transition:box-shadow .15s,transform .15s}.step-card:hover,.step-card:focus{box-shadow:0 8px 24px #15233a12;transform:translateY(-1px);outline:none}.step-card.status-degraded,.step-card.status-partial{border-left-color:var(--amber)}.step-card.status-failed{border-left-color:var(--red)}.step-card.status-skipped{border-left-color:#94a3b8}.step-head{display:flex;justify-content:space-between;align-items:center;gap:10px}.candidate{font-size:12px;color:#475569;font-weight:700;overflow-wrap:anywhere}.badge{display:inline-flex;align-items:center;border-radius:999px;padding:5px 9px;font-size:11px;font-weight:750;white-space:nowrap;background:#eff6ff;color:#1d4ed8}.badge.model{background:#f3e8ff;color:#6d28d9}.badge.rule{background:#dbeafe;color:#1d4ed8}.badge.ok{background:#dcfce7;color:#166534}.badge.degraded,.badge.partial,.badge.stalled{background:#fef3c7;color:#92400e}.badge.failed{background:#fee2e2;color:#991b1b}.badge.skipped{background:#f1f5f9;color:#475569}.step-card h3{margin:11px 0 3px;font-size:16px}.step-meta{font-size:12px;color:var(--muted)}.branches{display:flex;align-items:center;flex-wrap:wrap;gap:7px;margin-top:13px}.branch-label{font-size:11px;color:var(--muted);margin-right:2px}.branch{border:1px dashed #cbd5e1;border-radius:8px;padding:6px 8px;color:#64748b;background:#f8fafc;font-size:11px}.branch.selected{border:1px solid #93c5fd;background:#eff6ff;color:#1d4ed8;font-weight:700}.branch.selected.model{border-color:#d8b4fe;background:#faf5ff;color:#6d28d9}.outcomes{display:flex;flex-wrap:wrap;gap:7px;margin-top:12px}.pill{border:1px solid #ccfbf1;background:#f0fdfa;color:#115e59;border-radius:8px;padding:6px 8px;font-size:11px}.pill.evidence{border-color:#bae6fd;background:#f0f9ff;color:#075985}.pill.missing{border-color:#fde68a;background:#fffbeb;color:#92400e}.empty{border:1px dashed #cbd5e1;background:#fff;border-radius:14px;padding:28px;text-align:center;color:var(--muted)}.candidate-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(270px,1fr));gap:12px}.candidate-card{border:1px solid var(--line);background:#fff;border-radius:13px;padding:15px}.candidate-card header{display:flex;justify-content:space-between;gap:10px;align-items:center}.candidate-card h3{font-size:13px;margin:0;overflow-wrap:anywhere}.candidate-card p{font-size:12px;color:var(--muted);margin:12px 0 0}.facts{display:flex;flex-wrap:wrap;gap:6px;margin-top:9px}.fact{font-size:10px;border-radius:6px;padding:5px 7px;background:#fef3c7;color:#92400e}.fact.resolved{background:#dcfce7;color:#166534}.detail{position:fixed;inset:0 0 0 auto;width:min(440px,100vw);z-index:5;background:#fff;box-shadow:-20px 0 55px #0f172a24;padding:24px;overflow:auto;transform:translateX(105%);transition:transform .2s}.detail.open{transform:translateX(0)}.detail-top{display:flex;justify-content:space-between;align-items:center}.detail h2{font-size:19px}.close{border:1px solid var(--line);background:#fff;border-radius:9px;padding:7px 10px;cursor:pointer}.detail dl{display:grid;grid-template-columns:100px 1fr;gap:10px 12px;font-size:13px}.detail dt{color:var(--muted)}.detail dd{margin:0;overflow-wrap:anywhere}.detail pre{white-space:pre-wrap;overflow-wrap:anywhere;font:12px/1.55 ui-monospace,monospace;color:#334155;background:#f8fafc;border:1px solid var(--line);padding:12px;border-radius:10px}.foot{color:var(--muted);font-size:11px;margin-top:28px;border-top:1px solid var(--line);padding-top:14px}.hidden{display:none!important}@media(max-width:760px){.shell{padding-top:22px}.title-row{display:block}.run-chip{display:inline-block;margin-top:16px}.stats{grid-template-columns:repeat(2,minmax(0,1fr))}.stat:last-child{grid-column:span 2}.step{grid-template-columns:35px minmax(0,1fr);gap:8px}.step-index{width:35px;height:38px;border-radius:12px}.timeline:before{left:16px}.step-card{padding:13px}.step-head{align-items:flex-start}.toolbar input{min-width:100%}}
</style>
</head>
<body><main class="shell">
<div class="eyebrow">FirmHound · Agent Trace</div>
<div class="title-row"><div><h1>自主分析执行路径</h1><p class="subtitle">按真实执行顺序展示候选、规则筛出的合法动作、最终选择、证据变化和停止状态。虚线动作表示可选项；执行记录以实线步骤为准。</p></div><div class="run-chip">Run <b id="runId"></b></div></div>
<section class="stats" id="stats"></section>
<div class="toolbar"><label for="candidateFilter">候选筛选</label><select id="candidateFilter"><option value="">全部候选</option></select><label for="query">搜索</label><input id="query" type="search" placeholder="搜索动作、证据、缺失事实…"></div>
<div class="legend"><span><i class="dot rule"></i>规则选择</span><span><i class="dot model"></i>模型在合法动作中选择</span><span><i class="dot success"></i>成功 / 新证据</span><span><i class="dot warn"></i>降级 / 尚未解决</span><span><i class="dot fail"></i>失败</span><span><i class="dot alt"></i>未执行的合法备选</span></div>
<h2 class="section-title">动作轨迹</h2><section id="timeline" class="timeline"></section>
<h2 class="section-title">候选收敛情况</h2><section id="candidates" class="candidate-grid"></section>
<p class="foot">此视图来自 agent_trace.json。模型仅能选择规则筛选后的动作；漏洞结论仍由确定性验证阶段产生。HTML 自包含，无外部脚本、字体或网络请求。</p>
</main><aside id="detail" class="detail" aria-live="polite"><div class="detail-top"><h2>步骤详情</h2><button class="close" id="closeDetail">关闭</button></div><div id="detailContent"></div></aside>
<script>const DATA = """ + payload + r""";
const T=DATA.trace,L=DATA.labels,el=(tag,cls,text)=>{const n=document.createElement(tag);if(cls)n.className=cls;if(text!==undefined)n.textContent=String(text);return n};
const action=x=>L.actions[x]||x,fact=x=>L.facts[x]||x,status=x=>L.statuses[x]||x;
document.getElementById('runId').textContent=T.run_id||'unknown';
const s=T.summary||{},b=T.budget||{},m=T.model||{};
const stats=[['阶段状态',status(T.status)],['执行步数',`${s.steps||0} / ${b.max_steps||0}`],['新增证据',s.evidence_added||0],['模型调用',`${m.calls||0} 次`],['停止原因',s.stop_reason||'—']];
const statsNode=document.getElementById('stats');stats.forEach(([k,v])=>{const c=el('div','stat');c.append(el('span','',k),el('strong','',v));statsNode.append(c)});
const filter=document.getElementById('candidateFilter'),query=document.getElementById('query'),timeline=document.getElementById('timeline'),candidateGrid=document.getElementById('candidates');
const candidateIds=[...new Set([...(T.candidates||[]).map(x=>x.candidate_id),...(T.steps||[]).map(x=>x.candidate_id)])];candidateIds.forEach(id=>filter.append(el('option','',id)));
function showDetail(step){const panel=document.getElementById('detail'),body=document.getElementById('detailContent');body.replaceChildren();const rows=[['候选',step.candidate_id],['选择动作',action(step.selected_action)],['选择来源',step.selector==='model'?'模型排序':'规则排序'],['执行状态',status(step.status)],['耗时',`${step.duration_ms||0} ms`],['动作前指纹',step.signature_before||'—'],['动作后指纹',step.signature_after||'—']];const dl=el('dl');rows.forEach(([k,v])=>{dl.append(el('dt','',k),el('dd','',v))});body.append(dl);[['合法动作',step.eligible_actions||[],action],['产生事实',step.produced_facts||[],fact],['证据 ID',step.evidence_ids||[],x=>x],['执行前待查事实',step.missing_facts||[],fact]].forEach(([title,items,fmt])=>{body.append(el('h3','',title));const box=el('pre','',items.length?items.map(fmt).join('\n'):'无') ;body.append(box)});if(step.model_choice){body.append(el('h3','','模型选择摘要'));body.append(el('pre','',`${step.model_choice.action_id}\nconfidence=${step.model_choice.confidence}\n${step.model_choice.reason}`))}if(step.limitation)body.append(el('h3','','限制'),el('pre','',step.limitation));panel.classList.add('open')}
function render(){timeline.replaceChildren();candidateGrid.replaceChildren();const q=query.value.trim().toLowerCase(),cid=filter.value;const steps=T.steps||[];const visible=steps.filter(x=>(!cid||x.candidate_id===cid)&&(!q||JSON.stringify(x).toLowerCase().includes(q)));if(!visible.length){const msg=steps.length?'没有符合筛选条件的步骤。':'本次 Agent 未执行动作；请查看候选卡片中的缺失事实与停止状态。';timeline.append(el('div','empty',msg))}visible.forEach(step=>{const row=el('article','step');const index=el('div','step-index',`#${step.step}`);const card=el('div',`step-card status-${step.status||'unknown'}`);card.tabIndex=0;const head=el('div','step-head');head.append(el('span','candidate',step.candidate_id));const badges=el('div');badges.append(el('span',`badge ${step.selector||'rule'}`,step.selector==='model'?'模型选择':'规则选择'),' ');badges.append(el('span',`badge ${step.status||'unknown'}`,status(step.status)));head.append(badges);card.append(head,el('h3','',action(step.selected_action)),el('div','step-meta',`${step.duration_ms||0} ms · ${step.produced_facts?.length||0} 项新事实 · ${step.evidence_ids?.length||0} 条证据`));const branches=el('div','branches');branches.append(el('span','branch-label','规则筛选出的动作'));(step.eligible_actions||[]).forEach(a=>{const selected=a===step.selected_action;branches.append(el('span',`branch${selected?' selected '+(step.selector==='model'?'model':''):''}`,`${selected?'✓ ':'↳ '}${action(a)}`))});card.append(branches);const outcomes=el('div','outcomes');(step.produced_facts||[]).forEach(f=>outcomes.append(el('span','pill',`✓ ${fact(f)}`)));(step.evidence_ids||[]).forEach(e=>outcomes.append(el('span','pill evidence',`证据 ${e}`)));if(step.limitation)outcomes.append(el('span','pill missing',`限制：${step.limitation}`));if(outcomes.childNodes.length)card.append(outcomes);card.addEventListener('click',()=>showDetail(step));card.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();showDetail(step)}});row.append(index,card);timeline.append(row)});
const cmap=new Map((T.candidates||[]).map(c=>[c.candidate_id,c]));candidateIds.filter(id=>!cid||id===cid).filter(id=>!q||id.toLowerCase().includes(q)).forEach(id=>{const c=cmap.get(id)||{candidate_id:id,status:'unknown',initial_missing_facts:[],final_missing_facts:[],actions_attempted:[],evidence_added:[]};const card=el('article','candidate-card'),head=el('header');head.append(el('h3','',id),el('span',`badge ${c.status||'unknown'}`,status(c.status)));card.append(head);card.append(el('p','',`尝试 ${c.actions_attempted?.length||0} 个动作 · 新增 ${c.evidence_added?.length||0} 条证据 · 无进展 ${c.no_progress_streak||0} 次`));const facts=el('div','facts'),initial=new Set(c.initial_missing_facts||[]),remaining=new Set(c.final_missing_facts||[]);[...new Set([...initial,...remaining])].forEach(x=>facts.append(el('span',`fact ${remaining.has(x)?'':'resolved'}`,`${remaining.has(x)?'待查':'已补'} · ${fact(x)}`)));if(!facts.childNodes.length)facts.append(el('span','fact resolved','无待查事实'));card.append(facts);candidateGrid.append(card)})}
filter.addEventListener('change',render);query.addEventListener('input',render);document.getElementById('closeDetail').addEventListener('click',()=>document.getElementById('detail').classList.remove('open'));document.addEventListener('keydown',e=>{if(e.key==='Escape')document.getElementById('detail').classList.remove('open')});render();
</script></body></html>"""


def write_agent_visualization(run_dir: str | Path, trace: dict[str, Any]) -> Path:
    """Write/update the HTML view beside the trace and return its path."""
    path = Path(run_dir) / "artifacts" / "agent_execution.html"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(render_agent_visualization(trace), encoding="utf-8")
    temporary.replace(path)
    return path
