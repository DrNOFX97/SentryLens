"""
Gerador de relatório HTML autónomo com o estado do dashboard num dado
momento (KPIs, alertas, agentes, sistema). Função pura: recebe os dados já
recolhidos pelos endpoints existentes, nunca fala com o Wazuh diretamente.

IMPORTANTE (segurança): todo o texto dinâmico (nomes de agentes,
descrições de regra, full_log, etc.) TEM de passar por html.escape() antes
de entrar no HTML — este ficheiro é gravado em disco e reaberto
diretamente no browser sem passar pelo escapeHtml() do frontend (app.js),
que só protege o dashboard ao vivo. Sem isto, um atacante que controle
texto de um log do Windows (ex: nome de utilizador, descrição de um
processo) conseguiria injetar HTML/JS no relatório exportado — mesma
classe de vulnerabilidade já corrigida em app.js (XSS armazenado,
auditoria de 2026-08-31).
"""

import html
from datetime import datetime

MAX_ALERTS_ROWS = 500

_SEVERITY_LABELS = {
    "critical": "Crítico",
    "high": "Alto",
    "medium": "Médio",
    "low": "Baixo",
    "info": "Informativo",
}


def _esc(value) -> str:
    """html.escape() defensivo: nunca deixa 'None' aparecer literalmente."""
    if value is None:
        return "-"
    return html.escape(str(value))


def _fmt_timestamp(value: str) -> str:
    """Formata um timestamp ISO de forma legível; devolve o valor cru se não for parseável."""
    if not value:
        return "-"
    try:
        cleaned = value.replace("Z", "+00:00")
        dt = datetime.fromisoformat(cleaned)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return _esc(value)


def _render_kpis(stats: dict | None, agents: dict | None) -> str:
    if stats is None and agents is None:
        return '<p class="empty">Dados indisponíveis.</p>'

    cards = []

    if stats is not None:
        total_alerts = stats.get("total_alerts")
        cards.append(
            f'<div class="kpi-card"><div class="kpi-value">{_esc(total_alerts)}</div>'
            f'<div class="kpi-label">Total de alertas</div></div>'
        )

        by_severity = stats.get("by_severity") or {}
        for key, label in _SEVERITY_LABELS.items():
            if key in by_severity:
                cards.append(
                    f'<div class="kpi-card severity-{_esc(key)}">'
                    f'<div class="kpi-value">{_esc(by_severity.get(key))}</div>'
                    f'<div class="kpi-label">{_esc(label)}</div></div>'
                )
    else:
        cards.append('<p class="empty">Estatísticas indisponíveis.</p>')

    if agents is not None:
        summary = agents.get("summary") or {}
        for key, label in (
            ("active", "Agentes ativos"),
            ("disconnected", "Agentes desligados"),
            ("never_connected", "Nunca ligados"),
            ("total", "Total de agentes"),
        ):
            if key in summary:
                cards.append(
                    f'<div class="kpi-card">'
                    f'<div class="kpi-value">{_esc(summary.get(key))}</div>'
                    f'<div class="kpi-label">{_esc(label)}</div></div>'
                )
    else:
        cards.append('<p class="empty">Resumo de agentes indisponível.</p>')

    return f'<div class="kpi-grid">{"".join(cards)}</div>'


def _render_top_events(stats: dict | None) -> str:
    if stats is None:
        return '<p class="empty">Dados indisponíveis.</p>'

    top_events = stats.get("top_events") or []
    if not top_events:
        return '<p class="empty">Sem eventos no período selecionado.</p>'

    rows = []
    for event in top_events:
        rows.append(
            "<tr>"
            f"<td>{_esc(event.get('event_id'))}</td>"
            f"<td>{_esc(event.get('name'))}</td>"
            f"<td>{_esc(event.get('count'))}</td>"
            "</tr>"
        )

    return (
        '<table class="data-table">'
        "<thead><tr><th>Event ID</th><th>Nome</th><th>Contagem</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody>"
        "</table>"
    )


def _render_alerts(alerts: dict | None) -> str:
    if alerts is None:
        return '<p class="empty">Dados indisponíveis.</p>'

    alert_list = alerts.get("alerts") or []
    total = alerts.get("total", len(alert_list))

    if not alert_list:
        return '<p class="empty">Sem alertas no período selecionado.</p>'

    truncated = len(alert_list) > MAX_ALERTS_ROWS
    shown = alert_list[:MAX_ALERTS_ROWS]

    rows = []
    for alert in shown:
        severity = alert.get("severity")
        severity_label = _SEVERITY_LABELS.get(severity, severity)
        rows.append(
            f'<tr class="severity-row-{_esc(severity)}">'
            f"<td>{_esc(_fmt_timestamp(alert.get('timestamp')))}</td>"
            f"<td>{_esc(alert.get('agent_name'))}</td>"
            f"<td>{_esc(alert.get('windows_event_id'))}</td>"
            f"<td>{_esc(alert.get('friendly_name'))}</td>"
            f"<td>{_esc(severity_label)}</td>"
            f"<td>{_esc(alert.get('rule_description'))}</td>"
            "</tr>"
        )

    note = ""
    if truncated:
        note = (
            f'<p class="note">A mostrar os {MAX_ALERTS_ROWS} mais recentes '
            f"de {_esc(total)} totais.</p>"
        )

    table = (
        '<table class="data-table">'
        "<thead><tr><th>Timestamp</th><th>Agente</th><th>Event ID</th>"
        "<th>Nome amigável</th><th>Severidade</th><th>Descrição da regra</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody>"
        "</table>"
    )

    return note + table


def _render_agents(agents: dict | None) -> str:
    if agents is None:
        return '<p class="empty">Dados indisponíveis.</p>'

    agent_list = agents.get("agents") or []
    if not agent_list:
        return '<p class="empty">Sem agentes registados.</p>'

    rows = []
    for agent in agent_list:
        rows.append(
            "<tr>"
            f"<td>{_esc(agent.get('name'))}</td>"
            f"<td>{_esc(agent.get('ip'))}</td>"
            f"<td>{_esc(agent.get('status'))}</td>"
            f"<td>{_esc(agent.get('os'))}</td>"
            "</tr>"
        )

    return (
        '<table class="data-table">'
        "<thead><tr><th>Nome</th><th>IP</th><th>Estado</th><th>SO</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody>"
        "</table>"
    )


def _render_system(system_specs: dict | None) -> str:
    if system_specs is None:
        return '<p class="empty">Dados indisponíveis.</p>'

    cpu = system_specs.get("cpu") or {}
    ram = system_specs.get("ram") or {}
    disks = system_specs.get("disk") or []

    cards = []

    cpu_usage = cpu.get("usage_percent")
    if cpu_usage is not None:
        cards.append(
            f'<div class="kpi-card"><div class="kpi-value">{_esc(cpu_usage)}%</div>'
            f'<div class="kpi-label">CPU</div></div>'
        )

    ram_usage = ram.get("usage_percent")
    if ram_usage is not None:
        cards.append(
            f'<div class="kpi-card"><div class="kpi-value">{_esc(ram_usage)}%</div>'
            f'<div class="kpi-label">RAM</div></div>'
        )

    disk_rows = []
    for disk in disks:
        disk_rows.append(
            "<tr>"
            f"<td>{_esc(disk.get('mountpoint'))}</td>"
            f"<td>{_esc(disk.get('usage_percent'))}%</td>"
            "</tr>"
        )

    parts = []
    if cards:
        parts.append(f'<div class="kpi-grid">{"".join(cards)}</div>')
    else:
        parts.append('<p class="empty">Dados de CPU/RAM indisponíveis.</p>')

    if disk_rows:
        parts.append(
            '<table class="data-table">'
            "<thead><tr><th>Disco</th><th>Uso</th></tr></thead>"
            f"<tbody>{''.join(disk_rows)}</tbody>"
            "</table>"
        )
    else:
        parts.append('<p class="empty">Dados de disco indisponíveis.</p>')

    return "".join(parts)


def render_compliance_section(compliance_results: list[tuple[dict, dict]], org_profile: dict) -> str:
    """
    compliance_results: lista de tuplos (alerta, veredito), onde veredito é
    o dict devolvido por compliance_evaluator.evaluate_alert_compliance
    (este módulo NÃO importa compliance_evaluator — mantém-se puro, recebe
    já calculado, quem chama é responsável por avaliar). Devolve um bloco
    HTML (KPIs agregados por norma + tabela por alerta) pronto a passar
    como o argumento compliance_html de generate_html_report. Todo o texto
    dinâmico escapado com _esc(), mesma disciplina do resto do módulo.
    """
    if not compliance_results:
        return '<p class="empty">Sem alertas para avaliar conformidade neste período.</p>'

    counts = {
        "rgpd": {"aplicavel": 0, "verificado_e_nao_aplicavel": 0},
        "nis2": {"aplicavel": 0, "verificado_e_nao_aplicavel": 0},
        "ai_act": {"aplicavel": 0, "verificado_e_nao_aplicavel": 0},
    }
    rows = []
    for alert, compliance in compliance_results[:MAX_ALERTS_ROWS]:
        for norma in counts:
            estado = compliance.get(norma, {}).get("estado")
            if estado in counts[norma]:
                counts[norma][estado] += 1
        rows.append(
            "<tr>"
            f"<td>{_esc(_fmt_timestamp(alert.get('timestamp')))}</td>"
            f"<td>{_esc(alert.get('friendly_name'))}</td>"
            f"<td>{_esc(compliance.get('rgpd', {}).get('estado'))}</td>"
            f"<td>{_esc(compliance.get('nis2', {}).get('estado'))}</td>"
            f"<td>{_esc(compliance.get('ai_act', {}).get('estado'))}</td>"
            "</tr>"
        )

    kpi_cards = "".join(
        f'<div class="kpi-card"><div class="kpi-value">{_esc(counts[norma]["aplicavel"])}</div>'
        f'<div class="kpi-label">{_esc(label)} aplicável</div></div>'
        for norma, label in (("rgpd", "RGPD"), ("nis2", "NIS2"), ("ai_act", "AI Act"))
    )

    profile_note = (
        f'<p class="note">Perfil da organização: {_esc(org_profile.get("nome"))} — '
        f'sujeita a NIS2: {_esc("sim" if org_profile.get("estatuto_nis2_aplicavel") else "não")}, '
        f'componentes de IA ativos: {_esc("sim" if org_profile.get("tem_componentes_ia_ativos") else "não")}.</p>'
    )

    table = (
        '<table class="data-table">'
        "<thead><tr><th>Timestamp</th><th>Evento</th><th>RGPD</th><th>NIS2</th><th>AI Act</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody>"
        "</table>"
    )

    return f'<div class="kpi-grid">{kpi_cards}</div>{profile_note}{table}'


def generate_html_report(
    *,
    stats: dict | None,
    alerts: dict | None,
    agents: dict | None,
    system_specs: dict | None,
    generated_at: str,
    hours: int,
    compliance_html: str = "",
) -> str:
    """
    stats: resultado de GET /api/stats (ou None se a recolha falhou) —
        {"window_hours", "total_alerts", "by_severity", "by_category", "top_events", "by_agent"}
    alerts: resultado de GET /api/alerts (ou None) — {"total", "alerts": [...]}
        cada item de "alerts" tem os campos de _enrich_alert (timestamp,
        agent_name, agent_ip, rule_id, rule_description, wazuh_level,
        windows_event_id, friendly_name, severity, category,
        recommendation, full_log)
    agents: resultado de GET /api/agents (ou None) — {"agents": [...], "summary": {...}}
    system_specs: resultado de GET /api/system/specs (ou None) — specs da
        máquina local (cpu/ram/disk/network), estrutura variável, trata
        com .get() defensivo
    generated_at: timestamp ISO de quando o relatório foi gerado
    hours: janela temporal usada para os dados (para mostrar no cabeçalho)
    compliance_html: bloco HTML já pronto para a secção de conformidade da
        Fase 7 (ainda não existe) — vazio por agora, só para o contrato da
        função não mudar quando essa fase estiver pronta. Insere tal como
        vier (já deve vir escapado/seguro por quem o chamar no futuro).

    Devolve uma string HTML completa e autónoma (<!DOCTYPE html>...</html>),
    CSS embutido num <style> no <head>, ZERO pedidos a recursos externos
    (sem <link>/<script src> para fora, sem fontes do Google, etc.).

    Cada secção (stats/alerts/agents/system_specs) é opcional: se vier
    None, mostra uma mensagem "Dados indisponíveis" nessa secção em vez de
    rebentar — o relatório tem de se gerar sempre, mesmo com falhas
    parciais de recolha.
    """
    generated_at_label = _fmt_timestamp(generated_at)

    if system_specs is not None:
        system_section = f"""
    <section class="panel">
      <h2>Sistema</h2>
      {_render_system(system_specs)}
    </section>"""
    else:
        system_section = ""

    if compliance_html:
        compliance_section = f"""
    <section class="panel">
      <h2>Conformidade</h2>
      {compliance_html}
    </section>"""
    else:
        compliance_section = "\n    <!-- reservado para Fase 7 -->"

    return f"""<!DOCTYPE html>
<html lang="pt">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SentryLens — Relatório de Segurança</title>
<style>
  :root {{
    --navy-950: #0a1622;
    --navy-800: #12283c;
    --cyan-400: #2dd4e8;
    --cyan-600: #0b7d92;
    --cyan-700: #095e6f;
    --ink-900: #1a2530;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    padding: 0 16px 32px;
    font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
    color: var(--ink-900);
    background: #f4f7f9;
  }}
  header {{
    background: var(--navy-950);
    color: #ffffff;
    padding: 32px 24px;
    margin: 0 -16px 24px;
    border-bottom: 4px solid var(--cyan-400);
  }}
  header h1 {{
    margin: 0 0 8px;
    color: var(--cyan-400);
    font-size: 1.8rem;
  }}
  header p {{
    margin: 4px 0;
    color: #cfe8ee;
    font-size: 0.95rem;
  }}
  section.panel {{
    background: #ffffff;
    border: 1px solid #d7e2e7;
    border-radius: 8px;
    padding: 20px 24px;
    margin-bottom: 24px;
    max-width: 1200px;
  }}
  section.panel h2 {{
    margin-top: 0;
    color: var(--cyan-600);
    border-bottom: 2px solid var(--cyan-600);
    padding-bottom: 8px;
    font-size: 1.3rem;
  }}
  .kpi-grid {{
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
  }}
  .kpi-card {{
    background: var(--navy-800);
    color: #ffffff;
    border-radius: 6px;
    padding: 14px 18px;
    min-width: 140px;
    flex: 1 1 140px;
  }}
  .kpi-value {{
    font-size: 1.6rem;
    font-weight: 700;
    color: var(--cyan-400);
  }}
  .kpi-label {{
    font-size: 0.8rem;
    color: #cfe8ee;
    margin-top: 4px;
  }}
  table.data-table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: 12px;
    font-size: 0.85rem;
    overflow-x: auto;
    display: block;
  }}
  table.data-table th, table.data-table td {{
    text-align: left;
    padding: 6px 10px;
    border-bottom: 1px solid #e0e8eb;
    white-space: nowrap;
  }}
  table.data-table th {{
    background: #eef5f7;
    color: var(--cyan-700);
    position: sticky;
    top: 0;
  }}
  p.empty {{
    color: #6b7c85;
    font-style: italic;
  }}
  p.note {{
    color: #6b7c85;
    font-size: 0.85rem;
    margin-top: 12px;
  }}
  footer {{
    text-align: center;
    color: #8393a0;
    font-size: 0.8rem;
    margin-top: 32px;
  }}
</style>
</head>
<body>
  <header>
    <h1>SentryLens — Relatório de Segurança</h1>
    <p>Gerado em: {_esc(generated_at_label)}</p>
    <p>Janela temporal: últimas {_esc(hours)} horas</p>
  </header>

  <main>
    <section class="panel">
      <h2>KPIs</h2>
      {_render_kpis(stats, agents)}
    </section>

    <section class="panel">
      <h2>Top eventos</h2>
      {_render_top_events(stats)}
    </section>

    <section class="panel">
      <h2>Alertas</h2>
      {_render_alerts(alerts)}
    </section>

    <section class="panel">
      <h2>Agentes</h2>
      {_render_agents(agents)}
    </section>
{system_section}
{compliance_section}
  </main>

  <footer>
    <p>SentryLens — relatório gerado automaticamente, sem dependência do backend estar ativo para ser reaberto.</p>
  </footer>
</body>
</html>
"""
