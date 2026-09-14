# Troubleshooting

**Frontend mostra "● sem ligação"**
→ Confirma que o backend está a correr (`uvicorn main:app --port 8001`) e vê a consola do browser (F12) para o erro exato.

**Erro 502 "Erro ao contactar Wazuh Manager/Indexer"**
→ Confirma IP e passwords em `scripts/.env`, que a VM está a correr
(`VBoxManage list runningvms`), e testa a autenticação diretamente:
```bash
curl -k -u wazuh-wui:PASSWORD -X POST "https://IP_DA_VM:55000/security/user/authenticate?raw=true"
```

**VM `Running` mas não responde à rede**
→ Causa observada: soft lockups do kernel por I/O do OpenSearch quando
o disco `C:\` está quase cheio (o dashboard já assinala isto na aba
Sistema). Remédio imediato: `VBoxManage controlvm "Wazuh-Manager" poweroff`
seguido de `startvm ... --type headless`. Remédio de fundo: libertar
espaço em `C:\` ou mover o armazenamento da VM para outro disco.

**Erro 401 Unauthorized**
→ `SENTRYLENS_API_KEY` não definida em `scripts/.env`, ou a constante
`API_KEY` em `app.js` não é exatamente igual — reinicia o `uvicorn`
depois de editar `.env` (variáveis só são lidas no arranque).

**Dashboard nunca atualiza em tempo real**
→ Handshake de WebSocket com `api_key` errado/em falta falha
silenciosamente (código `1008`) — confirma na consola (F12 → Network →
"WS"). Não é bloqueante: o dashboard continua a funcionar via polling
de 30s.

**`uvicorn` falha com `WinError 10013` na porta 8000**
→ A porta 8000 já está ocupada neste PC por um serviço de terceiros
(`httpd.exe`/`IBXDashboard`) — usa `--port 8001`.

**CORS bloqueado no browser**
→ Acede via `localhost`/`127.0.0.1`, nunca `file://` diretamente.
Acesso a partir de outro dispositivo na rede exige alargar o CORS e
repensar autenticação, não é só reverter a restrição.

**Nenhum alerta aparece mesmo com o agente `Active`**
→ Gera um evento de teste (ex: `runas` com password errada → Event ID
4625) e confirma no próprio Wazuh Dashboard se aparece lá; se sim e
aqui não, o índice `wazuh-alerts-*` pode ter um nome diferente
consoante a versão.

**`ModuleNotFoundError: No module named 'fastapi'`**
→ `pip install -r scripts/requirements.txt` no mesmo ambiente Python
usado para correr `uvicorn`.
