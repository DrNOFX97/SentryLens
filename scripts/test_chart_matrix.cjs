"use strict";
// Teste node:vm da matriz de cobertura e da faixa ataque -> deteção (W6.4, W6.5).
const fs = require("node:fs");
const vm = require("node:vm");
const failures = [];
function check(l, c) { console.log(`[${c ? "OK   " : "FALHOU"}] ${l}`); if (!c) failures.push(l); }
const ctx = vm.createContext({});
vm.runInContext(fs.readFileSync(process.argv[2], "utf8"), ctx);

const atk = (id, scenario, ts, expected, achieved, mttd, mttdNet, verdict) => ({
  id, scenario, timestamp: ts, expected: { detection: expected },
  actual: { verdict: verdict || "detected", achieved, mttd_seconds: mttd, mttd_network_seconds: mttdNet },
});
const attacks = [
  atk(1, "brute_force", "2026-10-15T10:00:00+0000", ["rule", "network"], ["rule", "network"], 12, 3),
  atk(2, "brute_force", "2026-10-15T11:00:00+0000", ["rule", "network"], ["rule"], 8, null, "partial"),
  atk(3, "scan", "2026-10-15T09:00:00+0000", ["network"], [], null, null, "not_detected"),
  atk(4, "scan", "2026-10-15T09:30:00+0000", ["network"], ["ml"], 20, null, "partial"),
  atk(5, "priv_esc", "2026-10-15T12:00:00+0000", ["rule"], [], null, null, "unknown"),
];
const m = ctx.slCoverageMatrix(attacks);
const row = (n) => m.rows.find((r) => r.scenario === n);
check("unknown não entra na matriz mas é contado", m.unknown === 1 && !row("priv_esc"));
check("linhas por cenário, ordenadas", m.rows.map((r) => r.scenario).join(",") === "brute_force,scan");
check("rule em brute_force: esperado 2, alcançado 2 -> hit", row("brute_force").cells.rule.state === "hit" && row("brute_force").cells.rule.k === 2);
check("network em brute_force: 1 de 2 -> partial", row("brute_force").cells.network.state === "partial" && row("brute_force").cells.network.k === 1);
check("ml não esperado em brute_force -> none", row("brute_force").cells.ml.state === "none");
check("network em scan: esperado e falhado -> miss", row("scan").cells.network.state === "miss" && row("scan").cells.network.k === 0);
check("ml em scan: alcançado sem ser esperado -> extra", row("scan").cells.ml.state === "extra");
check("tentativas por cenário", row("brute_force").attempts === 2 && row("scan").attempts === 2);
check("sem dados -> matriz vazia", ctx.slCoverageMatrix(null).rows.length === 0 && ctx.slCoverageMatrix([]).unknown === 0);
const t = (s) => ctx.slMatrixCellText(row("brute_force").cells[s]);
check("texto de célula não depende só da cor", t("rule").text === "✔ 2/2" && t("network").text === "◐ 1/2" && ctx.slMatrixCellText(row("scan").cells.network).text === "✘ 0/2");
check("célula vazia -> travessão", ctx.slMatrixCellText(row("brute_force").cells.ml).text === "—");
check("descrição longa existe", t("network").label.includes("1 de 2"));

const strip = ctx.slAttackStrip(attacks);
check("faixa: mais antigo primeiro", strip.rows.map((r) => r.key).join(",") === "3,4,1,2,5");
check("faixa: rótulo com id e cenário", strip.rows.find((r) => r.key === "1").label === "#1 brute_force");
const r1 = strip.rows.find((r) => r.key === "1");
check("faixa: regra e rede com os seus MTTD", r1.points.length === 2 && r1.points.find((p) => p.sensor === "rule").seconds === 12 && r1.points.find((p) => p.sensor === "network").seconds === 3);
check("faixa: não detetado sem pontos", strip.rows.find((r) => r.key === "3").detected === false && strip.rows.find((r) => r.key === "3").points.length === 0);
check("faixa: deteção sem tempo conhecido não inventa ponto", ctx.slAttackStrip([atk(9, "x", "2026-10-15T10:00:00+0000", ["rule"], ["rule"], null, null)]).rows[0].points.length === 0);
check("eixo: máximo 20 s -> 20", strip.maxSeconds === 20);
check("eixo: 45 s -> 60", ctx.slAttackStrip([atk(1, "x", "2026-10-15T10:00:00+0000", ["rule"], ["rule"], 45, null)]).maxSeconds === 60);
check("eixo mínimo 20 s sem pontos", ctx.slAttackStrip([]).maxSeconds === 20);
check("eixo em minutos para MTTD longos", ctx.slAttackStrip([atk(1, "x", "2026-10-15T10:00:00+0000", ["rule"], ["rule"], 130, null)]).maxSeconds === 240);
if (failures.length) process.exit(1);
