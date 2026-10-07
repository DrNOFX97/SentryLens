"""
Testes de regressão da R6 (Network SOC): módulo puro network_soc.py,
persistência de deteções de rede em history_store.py (resolve a dívida de
R0 — "deteções de rede só existem em memória, perdem-se no restart"), e as
3 rotas novas em main.py (/api/network/live-traffic, /api/network/
detections, /api/network/evidence).

Mesmo estilo standalone dos outros ficheiros de teste do projeto:
check()/[OK]/[FALHOU], sys.exit(1) em caso de falha, SENTRYLENS_API_KEY
definida antes de "import main", main.app.router.on_startup.clear().

Correr:
    python test_network_soc.py
"""

import json
import os
import sys
import tempfile
from pathlib import Path

from history_store import (
    NETWORK_EVIDENCE_MAX_LIMIT,
    append_network_detection_history,
    append_network_detections_history,
    history_file_path,
    read_network_detection_history,
)
from network_soc import build_evidence_report, summarize_detections, summarize_packets

failures: list[str] = []


def check(label: str, condition: bool) -> None:
    print(f"[{'OK   ' if condition else 'FALHOU'}] {label}")
    if not condition:
        failures.append(label)


def _is_valid_json(linha: str) -> bool:
    try:
        json.loads(linha)
        return True
    except json.JSONDecodeError:
        return False


def packet(src_ip="192.168.1.170", dst_ip="192.168.1.20", protocol="TCP", dst_port=3389, timestamp="2026-10-07T10:00:00+00:00") -> dict:
    return {"timestamp": timestamp, "src_ip": src_ip, "dst_ip": dst_ip, "protocol": protocol, "dst_port": dst_port, "length": 66}


def detection(type_="port_scan", src_ip="192.168.1.170", dst_ip="192.168.1.20", timestamp="2026-10-07T10:00:00+00:00", detail=None) -> dict:
    return {"type": type_, "src_ip": src_ip, "dst_ip": dst_ip, "timestamp": timestamp, "detail": detail or {}}


def run_network_soc_pure_tests() -> None:
    # --- summarize_packets ---
    empty = summarize_packets([])
    check("summarize_packets([]) -> total 0", empty["total"] == 0)
    check("summarize_packets([]) -> window_start/end None", empty["window_start"] is None and empty["window_end"] is None)
    check("summarize_packets(None) não lança", summarize_packets(None)["total"] == 0)

    packets = [packet(src_ip=f"10.0.0.{i % 3}", timestamp=f"2026-10-07T10:00:{i:02d}+00:00") for i in range(5)]
    packets.append({"src_ip": None})  # malformado -> ignorado
    packets.append("não é um dict")  # malformado -> ignorado
    report = summarize_packets(packets)
    check("summarize_packets ignora pacotes malformados", report["total"] == 5)
    check("summarize_packets devolve by_protocol com TCP", report["by_protocol"].get("TCP") == 5)
    check("summarize_packets window_start/end da janela real", report["window_start"] == "2026-10-07T10:00:00+00:00" and report["window_end"] == "2026-10-07T10:00:04+00:00")
    check("summarize_packets top_talkers é lista não vazia", len(report["top_talkers"]) > 0)

    many_talkers = [packet(src_ip=f"10.0.0.{i}") for i in range(25)]
    report_many = summarize_packets(many_talkers)
    check("summarize_packets capa top_talkers a 10 mesmo com 25 origens distintas", len(report_many["top_talkers"]) == 10)

    # --- summarize_detections ---
    empty_dets = summarize_detections([], [])
    check("summarize_detections vazio -> live_count/history_count 0", empty_dets["live_count"] == 0 and empty_dets["history_count"] == 0)
    check("summarize_detections vazio -> recent []", empty_dets["recent"] == [])

    history = [detection(type_="port_scan", timestamp=f"2026-10-07T10:{i:02d}:00+00:00") for i in range(60)]
    live = [detection(type_="brute_force")]
    det_report = summarize_detections(live, history)
    check("summarize_detections live_count == 1", det_report["live_count"] == 1)
    check("summarize_detections history_count == 60", det_report["history_count"] == 60)
    check("summarize_detections capa 'recent' a 50", len(det_report["recent"]) == 50)
    check("summarize_detections 'recent' mais recente primeiro", det_report["recent"][0]["timestamp"] == "2026-10-07T10:59:00+00:00")
    check("summarize_detections by_type conta port_scan", det_report["by_type"].get("port_scan") == 60)

    # --- build_evidence_report ---
    ev = build_evidence_report([{"type": "port_scan"}], configured=True)
    check("build_evidence_report payload_capture é sempre False", ev["payload_capture"] is False)
    check("build_evidence_report total == len(entries)", ev["total"] == 1)
    ev_empty = build_evidence_report([], configured=False)
    check("build_evidence_report sem entradas -> total 0, configured refletido", ev_empty["total"] == 0 and ev_empty["configured"] is False)
    check("build_evidence_report(None, ...) não lança", build_evidence_report(None, True)["entries"] == [])


def run_history_store_tests() -> None:
    # --- append_network_detection_history escreve a linha esperada ---
    tmp1 = tempfile.mkdtemp()
    det1 = detection(type_="port_scan", src_ip="192.168.1.170", dst_ip="192.168.1.20", timestamp="2026-10-07T14:32:07+00:00", detail={"distinct_ports": 20})
    append_network_detection_history(det1, tmp1)
    path1 = history_file_path(tmp1, "2026-10-07", "network-detections")
    check("append_network_detection_history cria o ficheiro esperado", os.path.isfile(path1))
    with open(path1, "r", encoding="utf-8") as f:
        linhas1 = f.readlines()
    check("append_network_detection_history escreve 1 linha", len(linhas1) == 1)
    record1 = json.loads(linhas1[0])
    check("record.date == 2026-10-07", record1.get("date") == "2026-10-07")
    check("record.time == 14:32:07", record1.get("time") == "14:32:07")
    check("record.type == port_scan", record1.get("type") == "port_scan")
    check("record.src_ip/dst_ip corretos", record1.get("src_ip") == "192.168.1.170" and record1.get("dst_ip") == "192.168.1.20")
    check("record.detail preservado", record1.get("detail") == {"distinct_ports": 20})

    # --- timestamp ausente/inválido não lança ---
    tmp2 = tempfile.mkdtemp()
    try:
        append_network_detection_history({"type": "brute_force", "src_ip": "x", "dst_ip": "y"}, tmp2)
        sem_excecao = True
    except Exception:
        sem_excecao = False
    check("append_network_detection_history sem timestamp não lança", sem_excecao)

    # --- append_network_detections_history (batch) ---
    tmp3 = tempfile.mkdtemp()
    dets3 = [detection(timestamp=f"2026-10-07T09:0{i}:00+00:00") for i in range(3)]
    append_network_detections_history(dets3, tmp3)
    path3 = history_file_path(tmp3, "2026-10-07", "network-detections")
    with open(path3, "r", encoding="utf-8") as f:
        linhas3 = f.readlines()
    check("append_network_detections_history escreve 3 linhas para 3 deteções", len(linhas3) == 3)
    check("Todas as linhas são JSON válido", all(_is_valid_json(l) for l in linhas3))

    # --- read_network_detection_history: ordem mais recente primeiro ---
    tmp4 = tempfile.mkdtemp()
    for i in range(5):
        append_network_detection_history(detection(timestamp=f"2026-10-07T08:0{i}:00+00:00", detail={"n": i}), tmp4)
    lidas4 = read_network_detection_history(tmp4, date_str="2026-10-07")
    check("read_network_detection_history devolve as 5 entradas", len(lidas4) == 5)
    check("read_network_detection_history devolve mais recente primeiro", lidas4[0]["detail"]["n"] == 4 and lidas4[-1]["detail"]["n"] == 0)

    # --- limit aplica-se e é capeado mesmo pedindo mais que o teto ---
    check("read_network_detection_history respeita limit=2", len(read_network_detection_history(tmp4, date_str="2026-10-07", limit=2)) == 2)
    check(
        "read_network_detection_history capa limit a NETWORK_EVIDENCE_MAX_LIMIT mesmo pedindo mais",
        len(read_network_detection_history(tmp4, date_str="2026-10-07", limit=NETWORK_EVIDENCE_MAX_LIMIT + 10000)) == 5,
    )

    # --- dia sem dados / ficheiro ausente -> [] ---
    check("read_network_detection_history dia sem dados -> []", read_network_detection_history(tmp4, date_str="2026-01-01") == [])
    check("read_network_detection_history base_dir inexistente -> []", read_network_detection_history(os.path.join(tmp4, "nao-existe"), date_str="2026-10-07") == [])

    # --- data inválida -> [] (nunca lança, sem KeyError de mês inválido) ---
    check("read_network_detection_history com data malformada -> []", read_network_detection_history(tmp4, date_str="nao-e-uma-data") == [])
    check("read_network_detection_history com mês inválido -> [] (não levanta KeyError)", read_network_detection_history(tmp4, date_str="2026-99-99") == [])

    # --- leitura não cria diretórios para um dia sem dados (create=False) ---
    tmp5 = tempfile.mkdtemp()
    read_network_detection_history(tmp5, date_str="2026-05-05")
    check("Leitura de um dia sem dados não cria a pasta do mês", not os.path.isdir(os.path.join(tmp5, "2026", "05-maio")))

    # --- linha malformada no ficheiro é ignorada, não derruba a leitura ---
    tmp6 = tempfile.mkdtemp()
    append_network_detection_history(detection(timestamp="2026-10-07T12:00:00+00:00"), tmp6)
    path6 = history_file_path(tmp6, "2026-10-07", "network-detections")
    with open(path6, "a", encoding="utf-8") as f:
        f.write("isto nao e json\n")
        f.write("\n")  # linha vazia
    lidas6 = read_network_detection_history(tmp6, date_str="2026-10-07")
    check("Linha malformada/vazia é ignorada, resto é lido", len(lidas6) == 1)

    # --- "restart": persistir, recriar módulo de estado, reler do disco ---
    tmp7 = tempfile.mkdtemp()
    append_network_detections_history([detection(timestamp="2026-10-07T07:00:00+00:00")], tmp7)
    # Simula a perda do estado em memória (network_detection_buffer limpo) — a
    # evidência tem de continuar a vir do ficheiro, não da memória.
    buffer_em_memoria: list[dict] = []
    lidas7 = read_network_detection_history(tmp7, date_str="2026-10-07")
    check("Dados persistidos sobrevivem a 'restart' do estado em memória", len(lidas7) == 1 and len(buffer_em_memoria) == 0)


def run_api_tests() -> None:
    from unittest.mock import MagicMock

    from fastapi.testclient import TestClient

    from incident_store import IncidentStore

    os.environ.setdefault("SENTRYLENS_API_KEY", "chave-de-teste-nao-usar-em-producao")
    os.environ["VM_SSH_HOST"] = ""

    import main

    main.app.router.on_startup.clear()

    tmp_db = tempfile.mkdtemp()
    main.incident_store = IncidentStore(os.path.join(tmp_db, "i.sqlite3"))
    tmp_hist = tempfile.mkdtemp()
    main.SENTRYLENS_HISTORY_DIR = tmp_hist

    client = TestClient(main.app, headers={"X-API-Key": os.environ["SENTRYLENS_API_KEY"]})
    client_no_key = TestClient(main.app)

    # --- 401 sem X-API-Key, nas 3 rotas ---
    for path in ("/api/network/live-traffic", "/api/network/detections", "/api/network/evidence"):
        resp = client_no_key.get(path)
        check(f"GET {path} sem X-API-Key -> 401", resp.status_code == 401)

    # --- sem VM_SSH_HOST -> configured=False, zeros/vazios, nunca 500 ---
    main.vm_ssh_client = None
    resp_live = client.get("/api/network/live-traffic")
    check("GET /api/network/live-traffic sem captura -> 200", resp_live.status_code == 200)
    check("GET /api/network/live-traffic sem captura -> configured False, total 0", resp_live.json()["configured"] is False and resp_live.json()["total"] == 0)

    resp_dets = client.get("/api/network/detections")
    check("GET /api/network/detections sem captura -> 200, configured False", resp_dets.status_code == 200 and resp_dets.json()["configured"] is False)
    check("GET /api/network/detections sem captura -> live_count/history_count 0", resp_dets.json()["live_count"] == 0 and resp_dets.json()["history_count"] == 0)

    # --- evidence não depende de VM_SSH_HOST: lê ficheiro mesmo sem captura ativa ---
    resp_ev_vazio = client.get("/api/network/evidence")
    check("GET /api/network/evidence sem dados persistidos -> 200, entries []", resp_ev_vazio.status_code == 200 and resp_ev_vazio.json()["entries"] == [])
    check("GET /api/network/evidence -> payload_capture sempre False", resp_ev_vazio.json()["payload_capture"] is False)

    # --- com vm_ssh_client simulado e buffers com dados ---
    main.vm_ssh_client = MagicMock()
    main.packet_buffer.append(packet())
    main.network_detection_buffer.append(detection())

    resp_live2 = client.get("/api/network/live-traffic")
    check("GET /api/network/live-traffic configurado -> configured True, total 1", resp_live2.json()["configured"] is True and resp_live2.json()["total"] == 1)

    resp_dets2 = client.get("/api/network/detections")
    check("GET /api/network/detections configurado -> history_count 1", resp_dets2.json()["history_count"] == 1)

    main.packet_buffer.clear()
    main.network_detection_buffer.clear()
    main.vm_ssh_client = None

    # --- persistência: _ingest_incident_detections (callback real do poll loop) grava em disco ---
    main._ingest_incident_detections([detection(timestamp="2026-10-07T18:00:00+00:00", detail={"connections": 25})])
    resp_ev = client.get("/api/network/evidence", params={"date": "2026-10-07"})
    check("GET /api/network/evidence lê o que _ingest_incident_detections persistiu", resp_ev.json()["total"] == 1)
    check("GET /api/network/evidence devolve o detail persistido", resp_ev.json()["entries"][0]["detail"] == {"connections": 25})

    # --- limit/date validados pelo FastAPI (nunca sem teto) ---
    resp_limit_excessivo = client.get("/api/network/evidence", params={"limit": 999999})
    check("GET /api/network/evidence com limit > teto -> 422", resp_limit_excessivo.status_code == 422)
    resp_data_invalida = client.get("/api/network/evidence", params={"date": "não-é-uma-data"})
    check("GET /api/network/evidence com date malformada -> 422", resp_data_invalida.status_code == 422)
    resp_limit_valido = client.get("/api/network/evidence", params={"limit": 1, "date": "2026-10-07"})
    check("GET /api/network/evidence com limit=1 -> 1 entrada", resp_limit_valido.json()["total"] == 1)


if __name__ == "__main__":
    run_network_soc_pure_tests()
    run_history_store_tests()
    run_api_tests()

    print()
    if failures:
        print(f"[FALHOU] {len(failures)} teste(s) falharam: {failures}")
        sys.exit(1)
    print("[OK] Todos os testes passaram")
    sys.exit(0)
