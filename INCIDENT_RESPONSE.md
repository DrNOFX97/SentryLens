# 🚨 Plano de Resposta a Incidentes (IR)

**Projeto CET - Cibersegurança**
Plano de resposta a incidentes baseado no **NIST SP 800-61r2**, com playbooks práticos ligados diretamente aos alertas gerados pelo `log_analyzer.py` deste projeto.

---

## 📋 Objetivo

Definir um processo estruturado e repetível para detetar, conter, erradicar e recuperar de incidentes de segurança, minimizando impacto, tempo de indisponibilidade e perda de dados.

**Framework:** NIST SP 800-61r2 (4 fases) / mnemónica SANS **PICERL**:
`Preparation → Identification → Containment → Eradication → Recovery → Lessons Learned`

---

## 🔄 As 4 Fases do NIST SP 800-61

```
┌─────────────────┐     ┌──────────────────────┐     ┌───────────────────────────────┐     ┌────────────────────┐
│  1. PREPARAÇÃO   │ ──▶ │ 2. DETEÇÃO E ANÁLISE │ ──▶ │ 3. CONTENÇÃO, ERRADICAÇÃO   │ ──▶ │ 4. ATIVIDADE       │
│                  │     │                       │     │    E RECUPERAÇÃO             │     │    PÓS-INCIDENTE   │
└─────────────────┘     └──────────────────────┘     └───────────────────────────────┘     └────────────────────┘
        ▲                                                                                              │
        └──────────────────────────────── lições aprendidas alimentam a preparação ────────────────────┘
```

### Fase 1 — Preparação

- [ ] Equipa CSIRT definida (ver secção de Papéis)
- [ ] Contactos de emergência atualizados (interno, ISP, autoridades, jurídico)
- [ ] Ferramentas prontas: `log_analyzer.py`, EDR/antivírus, backups testados, imagem forense (ex: FTK Imager, KAPE)
- [ ] Playbooks (secção abaixo) documentados e testados via tabletop exercises
- [ ] Baseline de "normalidade" da rede/sistemas conhecida (facilita deteção de anomalias)
- [ ] Política de retenção de logs definida (mín. 90 dias, ideal 1 ano)

### Fase 2 — Deteção e Análise

- [ ] Fonte de deteção identificada (SIEM, EDR, utilizador, `log_analyzer.py`, terceiros)
- [ ] Evidência inicial recolhida **sem alterar o estado do sistema**
- [ ] Incidente classificado por **severidade** e **categoria** (ver matriz abaixo)
- [ ] Timeline preliminar construída (quando começou, o que foi afetado)
- [ ] Escalado ao responsável adequado consoante severidade

### Fase 3 — Contenção, Erradicação e Recuperação

- [ ] **Contenção a curto prazo**: isolar sistema afetado (rede, não desligar se preservação forense necessária)
- [ ] **Contenção a longo prazo**: aplicar patches temporários, alterar credenciais, bloquear IOCs
- [ ] **Erradicação**: remover malware/persistência, fechar vetor de entrada, revogar acessos comprometidos
- [ ] **Recuperação**: restaurar a partir de backup limpo, validar integridade, monitorização reforçada pós-recuperação
- [ ] Confirmar que a causa raiz foi corrigida antes de encerrar

### Fase 4 — Atividade Pós-Incidente

- [ ] Reunião de "lições aprendidas" (até 2 semanas após resolução)
- [ ] Relatório final documentado (ver template)
- [ ] Atualizar playbooks/regras de deteção com base no que foi aprendido
- [ ] Comunicar métricas à gestão (MTTD, MTTR — ver secção de Métricas)

---

## 🎯 Matriz de Classificação de Severidade

| Severidade | Critério | Tempo de Resposta Alvo | Exemplo |
|---|---|---|---|
| 🔴 **Crítica** | Impacto em produção, dados sensíveis expostos, ransomware ativo | Imediato (< 30 min) | Ransomware, exfiltração de dados confirmada |
| 🟠 **Alta** | Comprometimento confirmado, sem impacto generalizado ainda | < 2h | Conta admin comprometida, malware em endpoint crítico |
| 🟡 **Média** | Atividade suspeita, sem confirmação de comprometimento | < 8h | Múltiplas tentativas de login falhadas, phishing reportado sem clique |
| 🟢 **Baixa** | Evento informativo, risco baixo | < 24h | Scan de portas, política violada sem impacto |

---

## 👥 Papéis e Responsabilidades (CSIRT)

| Papel | Responsabilidade |
|---|---|
| **Incident Commander** | Coordena a resposta, toma decisões finais, comunica com gestão |
| **Analista de Segurança** | Investiga, analisa logs (`log_analyzer.py`, SIEM), identifica IOCs |
| **Administrador de Sistemas** | Executa contenção técnica, aplica patches, restaura backups |
| **Jurídico/DPO** | Avalia obrigações legais (ex: RGPD — notificação em 72h à CNPD se dados pessoais) |
| **Comunicação** | Gere comunicação interna e externa (clientes, imprensa se aplicável) |

> Em equipas pequenas, uma pessoa pode acumular vários papéis — o importante é que cada responsabilidade tenha um dono claro.

---

## 📖 Playbooks

### Playbook 1 — Força Bruta / Comprometimento de Conta

**Gatilho:** Alerta `anomaly_brute_force` ou Event ID `4625` (>5 falhas) gerado pelo `log_analyzer.py`

| Fase | Ações |
|---|---|
| **Identificação** | Confirmar utilizador e origem (IP) no relatório. Verificar se houve login bem-sucedido após as falhas (Event ID 4624 do mesmo IP/user) |
| **Contenção** | Bloquear/desativar a conta temporariamente. Bloquear IP de origem no firewall se externo |
| **Erradicação** | Forçar reset de password. Revogar sessões ativas e tokens MFA existentes |
| **Recuperação** | Reativar conta com nova password + MFA. Monitorizar atividade da conta 48h |
| **Lições Aprendidas** | Avaliar se política de lockout/MFA precisa de ajuste. Verificar se IP é recorrente noutros incidentes |

### Playbook 2 — Escalada de Privilégios Não Autorizada

**Gatilho:** Event ID `4672` (privilégios especiais) ou `4728`/`4756` (membro adicionado a grupo privilegiado) sem justificação conhecida

| Fase | Ações |
|---|---|
| **Identificação** | Confirmar se a alteração foi autorizada (change management / ticket associado) |
| **Contenção** | Remover privilégio/membro do grupo imediatamente se não autorizado |
| **Erradicação** | Investigar como a conta obteve capacidade de alterar grupos — possível conta já comprometida |
| **Recuperação** | Restaurar associação de grupos correta. Auditar todas as alterações do autor nas últimas 24-72h |
| **Lições Aprendidas** | Implementar aprovação dupla (4-eyes) para alterações a grupos privilegiados |

### Playbook 3 — Phishing

**Gatilho:** Utilizador reporta email suspeito, ou clique confirmado em link/anexo malicioso

| Fase | Ações |
|---|---|
| **Identificação** | Recolher o email original (cabeçalhos incluídos). Identificar quantos utilizadores receberam o mesmo email |
| **Contenção** | Remover o email de todas as caixas de correio (purge). Bloquear domínio/remetente/URL no gateway de email e proxy |
| **Erradicação** | Se houve clique: forçar reset de password do utilizador. Se houve execução de anexo: isolar endpoint e correr scan EDR completo |
| **Recuperação** | Reintegrar endpoint só após confirmação de limpeza. Reforçar MFA na conta afetada |
| **Lições Aprendidas** | Enviar aviso/formação aos utilizadores. Adicionar IOC (domínio, hash) a feeds de deteção |

### Playbook 4 — Ransomware

**Gatilho:** Ficheiros encriptados, nota de resgate, EDR alerta para comportamento de encriptação em massa

| Fase | Ações |
|---|---|
| **Identificação** | Confirmar âmbito: quantos sistemas afetados, que dados/partilhas de rede |
| **Contenção** | **Isolar imediatamente da rede** (desligar cabo/Wi-Fi) sistemas afetados — NÃO desligar a máquina (preserva memória para forense) |
| **Erradicação** | Identificar vetor de entrada (RDP exposto? phishing? vulnerabilidade?). Remover persistência. Não pagar resgate sem decisão de gestão/jurídico |
| **Recuperação** | Restaurar a partir do backup mais recente **validado como limpo** (anterior à infeção). Reconstruir sistemas do zero se necessário |
| **Lições Aprendidas** | Validar cadência e imutabilidade dos backups (3-2-1). Segmentação de rede para limitar propagação lateral |

### Playbook 5 — Alteração de Política de Segurança / Tarefa Agendada Suspeita

**Gatilho:** Event ID `4719` (política alterada) ou `4698` (tarefa agendada criada) sem autorização

| Fase | Ações |
|---|---|
| **Identificação** | Confirmar autor da alteração e comparar com change management |
| **Contenção** | Reverter alteração de política. Desativar a tarefa agendada suspeita sem apagar (preservar para análise) |
| **Erradicação** | Investigar conta/processo que fez a alteração — pode indicar persistência de atacante |
| **Recuperação** | Confirmar política restaurada ao estado esperado. Validar integridade de outras GPOs/tarefas |
| **Lições Aprendidas** | Restringir permissões de alteração de política a grupo reduzido de administradores |

---

## 📝 Template de Relatório de Incidente

```
ID DO INCIDENTE: INC-2026-XXX
DATA/HORA DE DETEÇÃO:
DATA/HORA DE RESOLUÇÃO:
SEVERIDADE: [Crítica / Alta / Média / Baixa]
CATEGORIA: [Força Bruta / Malware / Phishing / Ransomware / Outro]

RESUMO:
(Breve descrição do que aconteceu)

SISTEMAS/DADOS AFETADOS:

TIMELINE:
- HH:MM — Evento/ação
- HH:MM — Evento/ação

CAUSA RAIZ:

AÇÕES DE CONTENÇÃO:

AÇÕES DE ERRADICAÇÃO:

AÇÕES DE RECUPERAÇÃO:

IMPACTO (dados, downtime, financeiro):

NOTIFICAÇÃO REGULATÓRIA NECESSÁRIA? [Sim/Não — se Sim, RGPD 72h à CNPD]

LIÇÕES APRENDIDAS:

AÇÕES DE MELHORIA (com responsável e prazo):
```

---

## 📊 Métricas de Resposta a Incidentes

| Métrica | Definição | Meta |
|---|---|---|
| **MTTD** (Mean Time to Detect) | Tempo médio entre o incidente ocorrer e ser detetado | < 1h para eventos críticos |
| **MTTR** (Mean Time to Respond/Recover) | Tempo médio entre deteção e resolução completa | < 4h para severidade crítica |
| **Taxa de Falsos Positivos** | % de alertas que não eram incidentes reais | Minimizar sem perder deteções reais |
| **Nº de Incidentes por Categoria** | Tendência ao longo do tempo | Identificar padrões recorrentes |

---

## 🧪 Exercício Tabletop (Prática)

**Cenário sugerido para treino da equipa:**

> "São 09h15 de segunda-feira. O `log_analyzer.py` gera um alerta CRÍTICO: o utilizador `jsilva` teve 8 tentativas de login falhadas seguidas de um login bem-sucedido às 09h12, a partir de um IP externo nunca antes visto. Dez minutos depois, esse mesmo utilizador aparece no log com Event ID 4728 (adicionado ao grupo *Domain Admins*)."

**Perguntas para a equipa:**
1. Qual a severidade deste incidente e porquê?
2. Que playbook(s) se aplicam?
3. Quais as primeiras 3 ações concretas nos primeiros 15 minutos?
4. Que evidência deve ser preservada antes de qualquer remediação?
5. Quem precisa de ser notificado, e quando?

---

## 🔗 Integração com Este Projeto

Este plano foi desenhado para funcionar em conjunto com o `log_analyzer.py`:

1. O script analisa logs e gera alertas (`report.html` / `report.json`)
2. Cada tipo de alerta mapeia para um playbook específico acima
3. O analista segue o playbook correspondente e preenche o template de relatório
4. Casos resolvidos alimentam a fase de "Lições Aprendidas" e podem originar novas regras de deteção no `CRITICAL_EVENTS` do script

---

## 📚 Referências

- [NIST SP 800-61r2 — Computer Security Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [SANS Incident Handler's Handbook](https://www.sans.org/white-papers/33901/)
- [ENISA — Good Practice Guide for Incident Management](https://www.enisa.europa.eu/)
- RGPD Art. 33 — Notificação de violação de dados pessoais à autoridade de controlo (prazo de 72h)

---

**Projeto CET - Cibersegurança — FaroForma**
