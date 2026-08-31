#!/usr/bin/env python3
"""
Windows Event Log Analyzer
Análise de logs de segurança com geração de relatório HTML
Projeto CET - Cibersegurança
"""

import json
import csv
import re
import sys
from datetime import datetime
from collections import defaultdict, Counter
from pathlib import Path
from dataclasses import dataclass, asdict
import argparse

# A consola do Windows usa cp1252 por omissão, que não sabe codificar os
# carateres Unicode (✓, ✗, …) usados nas mensagens abaixo.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


@dataclass
class EventAlert:
    """Estrutura de um alerta/evento detectado"""
    event_id: str
    timestamp: str
    source: str
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    recommendation: str


class WindowsEventLogAnalyzer:
    """Analisador de Windows Event Logs com regras de cibersegurança"""
    
    # Mapeamento de Event IDs críticos (Windows Security)
    CRITICAL_EVENTS = {
        4625: {"name": "Failed Logon", "severity": "high", "pattern": "invalid"},
        4724: {"name": "Password Reset Attempt", "severity": "medium"},
        4732: {"name": "Member Added to Local Group", "severity": "medium"},
        4733: {"name": "Member Removed from Group", "severity": "medium"},
        4728: {"name": "Member Added to Global Group", "severity": "high"},
        4756: {"name": "Member Added to Universal Group", "severity": "high"},
        4720: {"name": "User Account Created", "severity": "medium"},
        4722: {"name": "User Account Enabled", "severity": "low"},
        4723: {"name": "Password Change Attempt", "severity": "low"},
        4726: {"name": "User Account Deleted", "severity": "high"},
        4738: {"name": "User Account Changed", "severity": "medium"},
        4781: {"name": "Computer Account Created", "severity": "medium"},
        4672: {"name": "Special Privileges Assigned", "severity": "high"},
        4688: {"name": "Process Created", "severity": "low"},
        4689: {"name": "Process Terminated", "severity": "low"},
        4698: {"name": "Scheduled Task Created", "severity": "high"},
        4699: {"name": "Scheduled Task Deleted", "severity": "medium"},
        4700: {"name": "Scheduled Task Disabled", "severity": "low"},
        4701: {"name": "Scheduled Task Updated", "severity": "medium"},
        4702: {"name": "Scheduled Task Renamed", "severity": "low"},
        4703: {"name": "Scheduled Task Enabled", "severity": "low"},
        4704: {"name": "User Right Assigned", "severity": "high"},
        4713: {"name": "Kerberos Policy Changed", "severity": "high"},
        4719: {"name": "Security Policy Changed", "severity": "high"},
        4797: {"name": "User Account Locked Out", "severity": "medium"},
        5140: {"name": "Network Share Accessed", "severity": "low"},
        5145: {"name": "Network Share Permission Checked", "severity": "low"},
    }
    
    def __init__(self):
        self.events = []
        self.alerts = []
        self.statistics = defaultdict(int)
    
    def parse_evtx_json(self, json_file_path):
        """Carrega eventos de um arquivo JSON (formato exportado de Windows Event Logs)"""
        try:
            with open(json_file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, list):
                    self.events = data
                elif isinstance(data, dict) and 'events' in data:
                    self.events = data['events']
                return len(self.events)
        except Exception as e:
            print(f"Erro ao ler arquivo JSON: {e}")
            return 0
    
    def parse_csv_logs(self, csv_file_path):
        """Carrega eventos de um arquivo CSV"""
        try:
            with open(csv_file_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                self.events = [row for row in reader]
                return len(self.events)
        except Exception as e:
            print(f"Erro ao ler arquivo CSV: {e}")
            return 0
    
    def analyze_events(self):
        """Executa análise de segurança nos eventos"""
        for event in self.events:
            event_id = event.get('EventID', event.get('event_id', ''))
            timestamp = event.get('TimeCreated', event.get('timestamp', ''))
            source = event.get('Computer', event.get('source', 'Unknown'))
            
            # Contagem geral
            self.statistics[f"event_{event_id}"] += 1
            self.statistics['total_events'] += 1
            
            # Detecção de eventos críticos
            try:
                event_id_int = int(event_id)
            except (TypeError, ValueError):
                event_id_int = None

            if event_id_int in self.CRITICAL_EVENTS:
                event_info = self.CRITICAL_EVENTS[event_id_int]

                alert = EventAlert(
                    event_id=str(event_id),
                    timestamp=timestamp,
                    source=source,
                    severity=event_info['severity'],
                    title=event_info['name'],
                    description=self._build_description(event),
                    recommendation=self._get_recommendation(str(event_id))
                )
                self.alerts.append(alert)
                self.statistics[f"severity_{event_info['severity']}"] += 1
        
        # Detecção de padrões suspeitos
        self._detect_anomalies()
    
    def _detect_anomalies(self):
        """Detecta padrões anómalos como brute force, múltiplos logons falhados, etc."""
        failed_logons = defaultdict(int)
        
        for event in self.events:
            # Contar tentativas de logon falhado por usuário
            if event.get('EventID') == 4625 or event.get('event_id') == '4625':
                user = event.get('TargetUserName', event.get('target_user', 'Unknown'))
                failed_logons[user] += 1
        
        # Gerar alerta se > 5 tentativas falhadas num utilizador
        for user, count in failed_logons.items():
            if count > 5:
                alert = EventAlert(
                    event_id="anomaly_brute_force",
                    timestamp=datetime.now().isoformat(),
                    source=user,
                    severity="critical",
                    title="Possível Ataque de Força Bruta Detectado",
                    description=f"Utilizador '{user}' teve {count} tentativas de logon falhadas",
                    recommendation="Bloquear conta temporariamente e investigar origem das tentativas"
                )
                self.alerts.append(alert)
                self.statistics['severity_critical'] += 1
    
    def _build_description(self, event):
        """Constrói descrição detalhada do evento"""
        event_id = event.get('EventID', event.get('event_id', ''))
        try:
            event_id = int(event_id)
        except (TypeError, ValueError):
            pass

        if event_id == 4625:  # Failed Logon
            return f"Falha de logon para utilizador {event.get('TargetUserName', 'Unknown')} de {event.get('IpAddress', 'Unknown')}"
        elif event_id == 4672:  # Special Privileges
            return f"Privilégios especiais atribuídos a {event.get('SubjectUserName', 'Unknown')}"
        elif event_id == 4698:  # Scheduled Task Created
            return f"Tarefa agendada criada: {event.get('TaskName', 'Unknown')}"
        else:
            return json.dumps(event, ensure_ascii=False)[:200]
    
    def _get_recommendation(self, event_id):
        """Retorna recomendação baseada no tipo de evento"""
        recommendations = {
            "4625": "Implementar bloqueio de conta após N falhas. Considerar MFA.",
            "4672": "Revisar porque foram necessários privilégios especiais. Validar legitimidade.",
            "4698": "Auditar tarefa agendada. Validar se foi criada por administrador autorizado.",
            "4726": "Investigar porque foi removida a conta. Verificar se foi intencional.",
            "4719": "Revisão urgente. Políticas de segurança foram alteradas.",
            "4713": "Revisar alterações na política Kerberos. Pode indicar comprometimento.",
            "anomaly_brute_force": "Bloquear conta e verificar logs de rede para IP origin.",
        }
        return recommendations.get(str(event_id), "Investigar e tomar ação apropriada.")
    
    def generate_html_report(self, output_file="report.html"):
        """Gera relatório HTML com visualização dos dados"""
        html_content = f"""
<!DOCTYPE html>
<html lang="pt-PT">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Relatório de Análise de Logs - Cibersegurança</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #333;
            line-height: 1.6;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        header {{
            background: white;
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 30px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        
        header h1 {{
            color: #1a1a2e;
            margin-bottom: 5px;
        }}
        
        header p {{
            color: #666;
            font-size: 14px;
        }}
        
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        
        .card h3 {{
            color: #1a1a2e;
            margin-bottom: 10px;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .card .value {{
            font-size: 32px;
            font-weight: bold;
            color: #0066cc;
        }}
        
        .card.critical .value {{
            color: #e74c3c;
        }}
        
        .card.high .value {{
            color: #f39c12;
        }}
        
        .card.medium .value {{
            color: #f1c40f;
        }}
        
        .card.low .value {{
            color: #27ae60;
        }}
        
        .alerts-section {{
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }}
        
        .alerts-section h2 {{
            color: #1a1a2e;
            margin-bottom: 20px;
            border-bottom: 2px solid #0066cc;
            padding-bottom: 10px;
        }}
        
        .alert-item {{
            padding: 15px;
            margin-bottom: 15px;
            border-left: 4px solid;
            border-radius: 4px;
            background: #f9f9f9;
        }}
        
        .alert-item.critical {{
            border-left-color: #e74c3c;
            background: #fadbd8;
        }}
        
        .alert-item.high {{
            border-left-color: #f39c12;
            background: #fdeaa8;
        }}
        
        .alert-item.medium {{
            border-left-color: #f1c40f;
            background: #ffffcc;
        }}
        
        .alert-item.low {{
            border-left-color: #27ae60;
            background: #d5f4e6;
        }}
        
        .alert-item.info {{
            border-left-color: #3498db;
            background: #d6eaf8;
        }}
        
        .alert-title {{
            font-weight: bold;
            margin-bottom: 5px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        .alert-badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
        }}
        
        .alert-item.critical .alert-badge {{
            background: #e74c3c;
            color: white;
        }}
        
        .alert-item.high .alert-badge {{
            background: #f39c12;
            color: white;
        }}
        
        .alert-item.medium .alert-badge {{
            background: #f1c40f;
            color: #333;
        }}
        
        .alert-item.low .alert-badge {{
            background: #27ae60;
            color: white;
        }}
        
        .alert-item.info .alert-badge {{
            background: #3498db;
            color: white;
        }}
        
        .alert-details {{
            font-size: 13px;
            color: #555;
            margin: 8px 0;
        }}
        
        .alert-recommendation {{
            background: rgba(0,0,0,0.05);
            padding: 10px;
            border-radius: 4px;
            margin-top: 10px;
            font-size: 13px;
            color: #333;
        }}
        
        .alert-recommendation strong {{
            color: #1a1a2e;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}
        
        table thead {{
            background: #f5f5f5;
        }}
        
        table th {{
            padding: 12px;
            text-align: left;
            font-weight: bold;
            color: #1a1a2e;
            border-bottom: 2px solid #ddd;
        }}
        
        table td {{
            padding: 12px;
            border-bottom: 1px solid #eee;
        }}
        
        table tbody tr:hover {{
            background: #f9f9f9;
        }}
        
        .no-alerts {{
            text-align: center;
            padding: 40px;
            color: #999;
        }}
        
        footer {{
            text-align: center;
            padding: 20px;
            color: #999;
            font-size: 12px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔒 Relatório de Análise de Windows Event Logs</h1>
            <p>Análise de cibersegurança — Projeto CET</p>
            <p>Gerado em {datetime.now().strftime('%d de %B de %Y às %H:%M:%S')}</p>
        </header>
        
        <div class="grid">
            <div class="card">
                <h3>Total de Eventos</h3>
                <div class="value">{self.statistics.get('total_events', 0)}</div>
            </div>
            <div class="card critical">
                <h3>Críticos</h3>
                <div class="value">{self.statistics.get('severity_critical', 0)}</div>
            </div>
            <div class="card high">
                <h3>Altos</h3>
                <div class="value">{self.statistics.get('severity_high', 0)}</div>
            </div>
            <div class="card medium">
                <h3>Médios</h3>
                <div class="value">{self.statistics.get('severity_medium', 0)}</div>
            </div>
            <div class="card low">
                <h3>Baixos</h3>
                <div class="value">{self.statistics.get('severity_low', 0)}</div>
            </div>
            <div class="card">
                <h3>Alertas Gerados</h3>
                <div class="value">{len(self.alerts)}</div>
            </div>
        </div>
        
        <div class="alerts-section">
            <h2>Alertas de Segurança</h2>
            {self._generate_alerts_html()}
        </div>
        
        <div class="alerts-section">
            <h2>Resumo de Eventos</h2>
            {self._generate_summary_html()}
        </div>
        
        <footer>
            <p>Este relatório é parte de um projeto educacional de cibersegurança.</p>
            <p>Consulte um especialista em segurança para análise detalhada e resposta a incidentes.</p>
        </footer>
    </div>
</body>
</html>
"""
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        return output_file
    
    def _generate_alerts_html(self):
        """Gera HTML com a lista de alertas"""
        if not self.alerts:
            return '<div class="no-alerts">✓ Nenhum alerta crítico detectado</div>'
        
        # Ordenar por severidade
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        sorted_alerts = sorted(self.alerts, key=lambda x: severity_order.get(x.severity, 5))
        
        html = ""
        for alert in sorted_alerts:
            html += f"""
            <div class="alert-item {alert.severity}">
                <div class="alert-title">
                    <span>{alert.title} (ID: {alert.event_id})</span>
                    <span class="alert-badge">{alert.severity}</span>
                </div>
                <div class="alert-details">
                    <strong>Fonte:</strong> {alert.source} | <strong>Data:</strong> {alert.timestamp}
                </div>
                <div class="alert-details">
                    {alert.description}
                </div>
                <div class="alert-recommendation">
                    <strong>Recomendação:</strong> {alert.recommendation}
                </div>
            </div>
            """
        
        return html
    
    def _generate_summary_html(self):
        """Gera tabela resumida dos eventos detectados"""
        event_counts = {
            k.replace('event_', ''): v 
            for k, v in self.statistics.items() 
            if k.startswith('event_')
        }
        
        if not event_counts:
            return '<p>Sem eventos para exibir.</p>'
        
        html = """
        <table>
            <thead>
                <tr>
                    <th>Event ID</th>
                    <th>Nome do Evento</th>
                    <th>Frequência</th>
                    <th>Severidade</th>
                </tr>
            </thead>
            <tbody>
        """
        
        for event_id, count in sorted(event_counts.items(), key=lambda x: x[1], reverse=True):
            try:
                event_id_int = int(event_id)
            except (TypeError, ValueError):
                event_id_int = None
            event_info = self.CRITICAL_EVENTS.get(event_id_int, {"name": "Desconhecido", "severity": "info"})
            html += f"""
                <tr>
                    <td>{event_id}</td>
                    <td>{event_info['name']}</td>
                    <td>{count}</td>
                    <td><span class="alert-badge" style="background: #3498db; color: white;">{event_info['severity']}</span></td>
                </tr>
            """
        
        html += """
            </tbody>
        </table>
        """
        
        return html
    
    def export_alerts_json(self, output_file="alerts.json"):
        """Exporta alertas para JSON"""
        alerts_data = [asdict(alert) for alert in self.alerts]
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump({
                'generated_at': datetime.now().isoformat(),
                'total_alerts': len(self.alerts),
                'statistics': dict(self.statistics),
                'alerts': alerts_data
            }, f, ensure_ascii=False, indent=2)
        return output_file


def main():
    parser = argparse.ArgumentParser(
        description='Analisador de Windows Event Logs com relatório de cibersegurança'
    )
    parser.add_argument('--input', '-i', help='Arquivo de input (JSON ou CSV)', required=True)
    parser.add_argument('--output', '-o', help='Arquivo HTML de output (default: report.html)', default='report.html')
    parser.add_argument('--export-json', help='Exportar alertas para JSON', action='store_true')
    
    args = parser.parse_args()
    
    # Verificar se arquivo existe
    if not Path(args.input).exists():
        print(f"Erro: Arquivo '{args.input}' não encontrado")
        return
    
    # Inicializar analisador
    analyzer = WindowsEventLogAnalyzer()
    
    # Carregar logs
    print(f"Carregando logs de {args.input}...")
    if args.input.endswith('.json'):
        count = analyzer.parse_evtx_json(args.input)
    elif args.input.endswith('.csv'):
        count = analyzer.parse_csv_logs(args.input)
    else:
        print("Erro: Suporta apenas arquivos JSON ou CSV")
        return
    
    print(f"Carregados {count} eventos")
    
    # Analisar
    print("Analisando eventos...")
    analyzer.analyze_events()
    
    # Gerar relatório
    print(f"Gerando relatório HTML: {args.output}")
    analyzer.generate_html_report(args.output)
    print(f"✓ Relatório gerado: {args.output}")
    
    # Exportar JSON se solicitado
    if args.export_json:
        json_file = args.output.replace('.html', '.json')
        analyzer.export_alerts_json(json_file)
        print(f"✓ Alertas exportados: {json_file}")


if __name__ == '__main__':
    main()
