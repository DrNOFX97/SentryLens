# ⚡ Quickstart — 3 Minutos

## 1️⃣ Testar Imediatamente

```bash
python log_analyzer.py --input sample_events.json --output report.html
```

Depois abre `report.html` num navegador. Vais ver:
- Dashboard com 20 eventos analisados
- 1 alerta CRÍTICO detectado (brute force)
- Recomendações de segurança

---

## 2️⃣ Com Teus Logs

Se tiveres logs do Windows, faz assim:

```bash
# Opção A: JSON (recomendado)
python log_analyzer.py --input teus_logs.json --output analise.html

# Opção B: CSV
python log_analyzer.py --input teus_logs.csv --output analise.html
```

---

## 3️⃣ Exportar Alertas para JSON

```bash
python log_analyzer.py --input sample_events.json --output report.html --export-json
```

Gera `report.json` com todos os alertas estruturados.

---

## 📊 O que Vês no Relatório

### Dashboard KPI
- Total de eventos
- Contagem por severidade
- Alertas gerados

### Alertas
Cada alerta mostra:
- **Tipo** (ex: Brute Force, Task Created, etc.)
- **Severidade** (Crítico, Alto, Médio, Baixo)
- **Fonte** (computador/utilizador)
- **Data** do evento
- **Descrição** detalhada
- **Recomendação** de ação

### Resumo
Tabela com todos os Event IDs e frequência.

---

## 🔧 Próximos Passos

1. **Testar com dados reais** — exporta logs da tua máquina
2. **Expandir regras** — adiciona mais Event IDs ao `CRITICAL_EVENTS`
3. **Dashboard Web** — usar este script como backend para React + FastAPI
4. **Laboratório** — integrar com Wazuh ou Security Onion

---

## 📞 Dúvidas?

Lê o `README.md` completo para documentação detalhada.
