> ⚠️ **Desatualizado** — descreve uma estrutura `backend/`/`frontend/`
> que já não existe (o layout real é `scripts/` + `index.html`/`app.js`/
> `style.css` na raiz). O [`README.md`](../README.md) da raiz do repo é
> a fonte de verdade atual; mantido aqui só pelo guia de troubleshooting
> ainda válido.

# 🔒 SentryLens — Fase 2

**Backend FastAPI + Frontend HTML/CSS, ligados ao Wazuh**

Esta é a Fase 2 do projeto: em vez de analisar ficheiros estáticos (Fase 1,
`log_analyzer_real.py`), o dashboard agora liga-se **ao vivo** ao laboratório
Wazuh montado em Hyper-V e mostra alertas em tempo real.

A classificação de eventos (Event ID → nome amigável, severidade,
recomendação) é a mesma lógica da Fase 1 — está centralizada em
`backend/event_catalog.py` para que as duas fases "falem a mesma língua".

---

## Estrutura

```
wazuh-dashboard/
├── backend/
│   ├── main.py              ← FastAPI app, endpoints REST
│   ├── wazuh_client.py      ← Cliente para Manager API + Indexer API
│   ├── event_catalog.py     ← Classificação de Event IDs (reaproveitado da Fase 1)
│   ├── test_with_mock.py    ← Testes sem precisar do Wazuh real ligado
│   ├── requirements.txt
│   └── .env.example
└── frontend/
    ├── index.html
    ├── style.css
    └── app.js
```

---

## Pré-requisito: Laboratório Wazuh

Este backend **precisa** do laboratório Wazuh a correr (ver
`LAB_WAZUH_HYPERV.md` da conversa anterior). Precisas de:

1. O IP da tua VM Wazuh (ex: `192.168.1.150`)
2. A password do utilizador `wazuh-wui` (Manager API, porta 55000)
3. A password do utilizador `admin` do Indexer (porta 9200)

Ambas as passwords estão no ficheiro gerado durante a instalação:
```bash
# Dentro da VM Ubuntu, na pasta onde correste o wazuh-install.sh
sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
```

---

## 1. Configurar o Backend

```bash
cd backend
pip install -r requirements.txt --break-system-packages
cp .env.example .env
```

Editar `.env` com os valores reais:
```env
WAZUH_MANAGER_URL=https://192.168.1.150:55000
WAZUH_MANAGER_USER=wazuh-wui
WAZUH_MANAGER_PASSWORD=<password real>

WAZUH_INDEXER_URL=https://192.168.1.150:9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASSWORD=<password real>
```

---

## 2. Testar Sem o Laboratório (opcional mas recomendado)

Antes de ligar ao Wazuh real, confirma que a lógica está correta:

```bash
python test_with_mock.py
```

Deve terminar com `✅ Todos os testes passaram`. Isto simula alertas do
Wazuh e valida classificação, agregações e deteção de brute force sem
precisares de nada ligado.

---

## 3. Correr o Backend

```bash
uvicorn main:app --reload --port 8001
```

> Nota: a porta 8000 está ocupada neste PC por um serviço Windows de
> terceiros (`httpd.exe` / serviço `IBXDashboard`), por isso o backend
> usa 8001 como default do projeto.

Confirma que está de pé:
```bash
curl http://localhost:8001/api/health
```

Documentação interativa automática (Swagger) disponível em:
```
http://localhost:8001/docs
```//
Aqui consegues testar cada endpoint diretamente no browser antes de ligar o frontend.

---

## 4. Abrir o Frontend

O frontend é HTML/CSS/JS puro — não precisa de build nem de servidor
especial. Duas opções:

**A. Abrir diretamente**
```
Fazer duplo-clique em frontend/index.html
```

**B. Servir com um servidor estático simples** (evita alguns problemas de CORS/cache)
```bash
cd frontend
python -m http.server 5500
```
Depois abrir `http://localhost:5500`

---

## Endpoints Disponíveis

| Endpoint | Descrição |
|---|---|
| `GET /api/health` | Confirma que o backend está de pé |
| `GET /api/agents` | Lista de agentes Wazuh e o seu estado |
| `GET /api/alerts?hours=24&severity=high` | Alertas recentes, já classificados |
| `GET /api/stats?hours=24` | KPIs agregados (por severidade, top eventos, por agente) |
| `GET /api/brute-force?hours=24&threshold=5` | Utilizadores com tentativas de logon falhadas acima do limite |

---

## O Que o Dashboard Mostra

- **KPIs** — total de alertas e contagem por severidade (crítico/alto/médio/baixo)
- **Alertas recentes** — lista ordenada por severidade, com recomendação de ação
- **Deteção de brute force** — painel destacado quando há utilizadores com
  tentativas de logon falhadas repetidas (mesma lógica da Fase 1)
- **Agentes** — estado de ligação de cada máquina monitorizada
- **Top eventos** — quais Event IDs aparecem com mais frequência

Atualiza automaticamente a cada 30 segundos, ou manualmente com o botão
"Atualizar".

---

## Troubleshooting

**Frontend mostra "● sem ligação"**
→ Confirma que o backend está a correr (`uvicorn main:app --port 8001`)
→ Abre a consola do browser (F12) e vê o erro exato

**Erro 502 "Erro ao contactar Wazuh Manager/Indexer"**
→ Confirma o IP e passwords no `.env`
→ Testa a ligação diretamente:
```bash
curl -k -u wazuh-wui:PASSWORD -X POST "https://IP_WAZUH:55000/security/user/authenticate?raw=true"
```
Se isto falhar, o problema é de rede/credenciais, não do backend.

**CORS bloqueado no browser**
→ O backend já tem CORS aberto (`allow_origins=["*"]`) para desenvolvimento.
Se ainda houver bloqueio, confirma que estás a aceder ao frontend via
`http://` e não via `file://` diretamente (usar a opção B do passo 4).

**Nenhum alerta aparece mesmo com o agente ativo**
→ Confirma que já geraste algum evento de teste na máquina Windows (ex:
logon falhado) depois de instalar o agente
→ Confirma no próprio Wazuh Dashboard (`https://IP_WAZUH`) se os alertas
lá aparecem — se sim e aqui não, o problema está na query ao índice
(`wazuh-alerts-*` pode ter um nome ligeiramente diferente consoante a
versão; confirma em Indexer Management → Index Patterns)

---

## Próximos Passos

1. **Autenticação no dashboard** — atualmente qualquer pessoa na rede local
   consegue aceder; para produção, adicionar login simples
2. **Websockets** — substituir o polling de 30s por atualização em tempo real
3. **Persistência** — guardar histórico de alertas numa base de dados própria
   (o Wazuh só guarda 90 dias por default)
4. **Exportar relatório** — botão para gerar o mesmo tipo de relatório HTML
   da Fase 1, mas com dados ao vivo
