"""
Monitor de specs e saúde do sistema (Fase 2 — SentryLens).

Recolhe métricas locais da máquina (CPU, RAM, disco, rede) via psutil,
mede velocidade de rede via Ookla Speedtest CLI, e mantém histórico de
violações de threshold. Não depende do Wazuh — é sobre a máquina onde
o backend corre.
"""

import json
import os
import platform
import shutil
import socket
import subprocess
from collections import deque
from datetime import datetime, timezone

import psutil

# speedtest-cli (biblioteca Python pura) satura tipicamente por volta dos
# 400-500 Mbps por ser single-thread — não consegue medir ligações gigabit
# com precisão. Usamos antes o binário oficial Ookla Speedtest CLI
# (multi-thread), instalado via `winget install Ookla.Speedtest.CLI`.
_SPEEDTEST_FALLBACK_PATH = (
    r"C:\Users\Fernando Nuno\AppData\Local\Microsoft\WinGet\Links\speedtest.exe"
)


def _find_speedtest_binary() -> str:
    on_path = shutil.which("speedtest")
    if on_path:
        return on_path
    if os.path.exists(_SPEEDTEST_FALLBACK_PATH):
        return _SPEEDTEST_FALLBACK_PATH
    raise RuntimeError(
        "Ookla Speedtest CLI não encontrado. Instala com: "
        "winget install --id Ookla.Speedtest.CLI -e"
    )


def _cpu_info() -> dict:
    freq = psutil.cpu_freq()
    return {
        "model": platform.processor() or "Desconhecido",
        "physical_cores": psutil.cpu_count(logical=False),
        "logical_cores": psutil.cpu_count(logical=True),
        "frequency_mhz": round(freq.current, 2) if freq else None,
        "usage_percent": psutil.cpu_percent(interval=0.5),
    }


# SMBIOS Type 17 "Memory Type" — só os valores que interessam para specs
# domésticos/desktop modernos (a spec completa tem ~40 valores legacy).
_SMBIOS_MEMORY_TYPES = {
    20: "DDR",
    21: "DDR2",
    24: "DDR3",
    26: "DDR4",
    34: "DDR5",
}


def _ram_modules() -> list[dict]:
    """
    Detalhe físico de cada módulo de RAM instalado (fabricante, part number,
    capacidade, velocidade, geração DDR), via Win32_PhysicalMemory do WMI.

    Windows-only, como o resto deste módulo. Uma falha aqui não deve derrubar
    o resto dos specs — devolve [] e o card de RAM fica só sem o detalhe físico.
    """
    script = (
        "Get-CimInstance -ClassName Win32_PhysicalMemory | ForEach-Object { "
        "[PSCustomObject]@{ DeviceLocator = $_.DeviceLocator; "
        "Manufacturer = $_.Manufacturer; PartNumber = ($_.PartNumber -as [string]).Trim(); "
        "Capacity = $_.Capacity; Speed = $_.Speed; "
        "SMBIOSMemoryType = $_.SMBIOSMemoryType } } | ConvertTo-Json -Compress"
    )
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", script],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return []
        data = json.loads(proc.stdout)
        if isinstance(data, dict):
            data = [data]
        return [
            {
                "device_locator": entry.get("DeviceLocator"),
                "manufacturer": entry.get("Manufacturer"),
                "part_number": entry.get("PartNumber"),
                "capacity_bytes": entry.get("Capacity"),
                "speed_mhz": entry.get("Speed"),
                "memory_type": _SMBIOS_MEMORY_TYPES.get(entry.get("SMBIOSMemoryType"), "Desconhecido"),
            }
            for entry in data
        ]
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        return []


def _ram_info() -> dict:
    mem = psutil.virtual_memory()
    return {
        "total_bytes": mem.total,
        "used_bytes": mem.used,
        "available_bytes": mem.available,
        "usage_percent": mem.percent,
        "modules": _ram_modules(),
    }


def _physical_disk_map() -> dict[str, dict]:
    """
    Mapeia letra de drive (ex: "C") -> {model, media_type, bus_type} do disco
    físico por trás dela, via Get-Partition/Get-PhysicalDisk do PowerShell.

    Windows-only, como o resto deste módulo (speedtest.exe, etc.). Uma falha
    aqui (PowerShell indisponível, timeout, disco de rede sem
    Get-PhysicalDisk) não deve derrubar o resto dos specs — devolve {} e os
    cards de disco ficam só sem o detalhe físico.
    """
    script = (
        "Get-Partition | Where-Object DriveLetter | ForEach-Object { "
        "$d = Get-PhysicalDisk -DeviceNumber $_.DiskNumber; "
        "[PSCustomObject]@{ DriveLetter = [string]$_.DriveLetter; "
        "Model = $d.FriendlyName; MediaType = [string]$d.MediaType; "
        "BusType = [string]$d.BusType } } | ConvertTo-Json -Compress"
    )
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", script],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return {}
        data = json.loads(proc.stdout)
        if isinstance(data, dict):
            data = [data]
        return {
            entry["DriveLetter"]: {
                "model": entry.get("Model"),
                "media_type": entry.get("MediaType"),
                "bus_type": entry.get("BusType"),
            }
            for entry in data
            if entry.get("DriveLetter")
        }
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        return {}


def _disk_info() -> list[dict]:
    physical_by_letter = _physical_disk_map()
    partitions = []
    for part in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(part.mountpoint)
        except (PermissionError, OSError):
            continue
        drive_letter = part.mountpoint.rstrip("\\").rstrip(":")
        physical = physical_by_letter.get(drive_letter, {})
        partitions.append({
            "device": part.device,
            "mountpoint": part.mountpoint,
            "filesystem": part.fstype,
            "total_bytes": usage.total,
            "used_bytes": usage.used,
            "free_bytes": usage.free,
            "usage_percent": usage.percent,
            "physical_model": physical.get("model"),
            "media_type": physical.get("media_type"),
            "bus_type": physical.get("bus_type"),
        })
    return partitions


def _network_info() -> list[dict]:
    interfaces = []
    stats = psutil.net_if_stats()
    for name, addrs in psutil.net_if_addrs().items():
        if name not in stats or not stats[name].isup:
            continue
        ipv4 = next((a.address for a in addrs if a.family == socket.AF_INET), None)
        if not ipv4:
            continue
        interfaces.append({
            "interface": name,
            "ip": ipv4,
            "speed_mbps": stats[name].speed or None,
        })
    return interfaces


def get_specs() -> dict:
    """Snapshot actual de CPU, RAM, disco e rede desta máquina."""
    return {
        "cpu": _cpu_info(),
        "ram": _ram_info(),
        "disk": _disk_info(),
        "network": _network_info(),
    }


# Última medição de velocidade de rede, guardada em memória. speedtest-cli
# demora vários segundos e satura o link, por isso só corre quando chamada
# explicitamente (endpoint POST ou scheduler da Etapa 4), nunca por pedido HTTP.
_last_speedtest: dict | None = None


def measure_network_speed() -> dict:
    """Mede download/upload actuais via Ookla Speedtest CLI e guarda o resultado em cache."""
    global _last_speedtest

    binary = _find_speedtest_binary()
    proc = subprocess.run(
        [binary, "--accept-license", "--accept-gdpr", "--format=json"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"Speedtest CLI falhou (código {proc.returncode}): {proc.stderr.strip()}")

    result = json.loads(proc.stdout.strip().splitlines()[-1])

    # bandwidth vem em bytes/s; Mbps = bytes/s * 8 / 1_000_000
    _last_speedtest = {
        "download_mbps": round(result["download"]["bandwidth"] * 8 / 1_000_000, 2),
        "upload_mbps": round(result["upload"]["bandwidth"] * 8 / 1_000_000, 2),
        "ping_ms": round(result["ping"]["latency"], 2),
        "server": result["server"].get("name"),
        "measured_at": datetime.now(timezone.utc).isoformat(),
    }
    return _last_speedtest


def get_last_network_speed() -> dict | None:
    """Devolve a última medição de rede em cache (None se nunca correu)."""
    return _last_speedtest


# --- Histórico de uso de CPU/RAM/disco ---------------------------------------

# Buffer simples em memória (não persiste a reinícios do processo) com as
# últimas amostras de uso, alimentado pelo loop de background a cada 30s.
# 120 amostras a 30s ≈ 1h de histórico. Vive no backend para que qualquer
# separador/browser que abra o dashboard veja o mesmo histórico, em vez de
# cada aba acumular o seu próprio buffer que se perde ao recarregar.
USAGE_HISTORY_MAX = 120
_usage_history: deque[dict] = deque(maxlen=USAGE_HISTORY_MAX)


def record_usage_sample(specs: dict) -> dict:
    """Extrai CPU/RAM/disco de `specs` (formato get_specs()) e guarda uma amostra no buffer."""
    disks = specs.get("disk") or []
    primary_disk = disks[0] if disks else None

    sample = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "cpu_percent": specs.get("cpu", {}).get("usage_percent"),
        "ram_percent": specs.get("ram", {}).get("usage_percent"),
        "disk_percent": primary_disk.get("usage_percent") if primary_disk else None,
        "disk_mountpoint": primary_disk.get("mountpoint") if primary_disk else None,
    }
    _usage_history.append(sample)
    return sample


def get_usage_history() -> list[dict]:
    """Devolve o buffer de amostras de uso, da mais antiga para a mais recente."""
    return list(_usage_history)


# --- Thresholds e histórico de transições -----------------------------------

THRESHOLDS = {
    "ram": {"warning": 85, "critical": 95},
    "disk": {"warning": 80, "critical": 90},
    "network": {"warning": 700, "critical": 500},
}

_HISTORY_PATH = os.path.join(os.path.dirname(__file__), "system_alerts_history.json")


def _level_above(value: float | None, warning: float, critical: float) -> str | None:
    """Nível de violação quando o valor é preocupante ao SUBIR (RAM, disco)."""
    if value is None:
        return None
    if value >= critical:
        return "critico"
    if value >= warning:
        return "aviso"
    return None


def _level_below(value: float | None, warning: float, critical: float) -> str | None:
    """Nível de violação quando o valor é preocupante ao DESCER (rede)."""
    if value is None:
        return None
    if value < critical:
        return "critico"
    if value < warning:
        return "aviso"
    return None


def _duration_seconds(started_at: str, resolved_at: str) -> float:
    start = datetime.fromisoformat(started_at)
    end = datetime.fromisoformat(resolved_at)
    return round((end - start).total_seconds(), 3)


def _load_history() -> list[dict]:
    if not os.path.exists(_HISTORY_PATH):
        return []
    with open(_HISTORY_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_history(entries: list[dict]) -> None:
    with open(_HISTORY_PATH, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2, ensure_ascii=False)


def _current_metric_levels(specs: dict) -> dict[str, str | None]:
    """Calcula o nível actual (None/aviso/critico) de cada métrica monitorizada."""
    levels: dict[str, str | None] = {}

    ram_pct = specs.get("ram", {}).get("usage_percent")
    levels["ram"] = _level_above(ram_pct, **_kw(THRESHOLDS["ram"]))

    for disk in specs.get("disk", []):
        metric_name = f"disk:{disk.get('mountpoint')}"
        levels[metric_name] = _level_above(disk.get("usage_percent"), **_kw(THRESHOLDS["disk"]))

    network = specs.get("network_speed")
    if network:
        levels["network_download"] = _level_below(network.get("download_mbps"), **_kw(THRESHOLDS["network"]))
        levels["network_upload"] = _level_below(network.get("upload_mbps"), **_kw(THRESHOLDS["network"]))

    return levels


def _kw(threshold_pair: dict) -> dict:
    return {"warning": threshold_pair["warning"], "critical": threshold_pair["critical"]}


def get_history() -> list[dict]:
    """Devolve o histórico completo de violações de threshold (activas e resolvidas)."""
    return _load_history()


def check_thresholds(specs: dict) -> dict:
    """
    Compara `specs` (formato de get_specs(), opcionalmente com uma chave
    "network_speed" = get_last_network_speed()) contra os THRESHOLDS.

    Regista transições em system_alerts_history.json: abre uma entrada
    quando uma métrica passa a violada, fecha-a (com resolved_at e
    duration_seconds) quando volta ao normal ou muda de nível.

    Devolve {"active_violations": [...], "history": [...]}.
    """
    history = _load_history()
    now = datetime.now(timezone.utc).isoformat()

    metric_levels = _current_metric_levels(specs)
    open_by_metric = {e["metric"]: e for e in history if e["resolved_at"] is None}

    for metric, level in metric_levels.items():
        open_entry = open_by_metric.get(metric)

        if level is None:
            if open_entry is not None:
                open_entry["resolved_at"] = now
                open_entry["duration_seconds"] = _duration_seconds(open_entry["started_at"], now)
            continue

        if open_entry is None:
            history.append({"metric": metric, "level": level, "started_at": now, "resolved_at": None})
        elif open_entry["level"] != level:
            open_entry["resolved_at"] = now
            open_entry["duration_seconds"] = _duration_seconds(open_entry["started_at"], now)
            history.append({"metric": metric, "level": level, "started_at": now, "resolved_at": None})

    _save_history(history)

    return {
        "active_violations": [e for e in history if e["resolved_at"] is None],
        "history": [e for e in history if e["resolved_at"] is not None],
    }


if __name__ == "__main__":
    print(json.dumps(get_specs(), indent=2, ensure_ascii=False))
