"use strict";
// Teste node:vm dos helpers de dados dos gráficos de ui_helpers.js (W6).
const fs = require("node:fs");
const vm = require("node:vm");
const failures = [];
function check(l, c) { console.log(`[${c ? "OK   " : "FALHOU"}] ${l}`); if (!c) failures.push(l); }
const ctx = vm.createContext({});
vm.runInContext(fs.readFileSync(process.argv[2], "utf8"), ctx);

check("1 h -> baldes de 5 min", ctx.slBucketGranularity(1) === "5min");
check("6 h -> baldes de 30 min", ctx.slBucketGranularity(6) === "30min");
check("24 h e 48 h -> horas", ctx.slBucketGranularity(24) === "hour" && ctx.slBucketGranularity(48) === "hour");
check("168 h -> dias", ctx.slBucketGranularity(168) === "day");

// 15/10/2026 14:20 local; 24 h -> baldes horários contínuos (25, das 14h do dia anterior às 14h).
const now = new Date(2026, 9, 15, 14, 20, 0).getTime();
const t = (d, h, m) => new Date(2026, 9, d, h, m, 0).toISOString();
const b24 = ctx.slBucketSeries([t(15, 14, 5), t(15, 14, 50), t(15, 9, 1), t(14, 14, 30)], 24, now);
check("24 h: baldes contínuos (25)", b24.length === 25);
check("24 h: último balde às 14 h tem 2", b24[b24.length - 1].label === "14 h" && b24[b24.length - 1].count === 2);
check("24 h: horas vazias valem 0 e não desaparecem", b24.filter((b) => b.count === 0).length === 22);
check("24 h: soma dos baldes = alertas dentro da janela", b24.reduce((a, b) => a + b.count, 0) === 4);
check("baldes ordenados e sem repetições", b24.every((b, i) => i === 0 || b.startMs > b24[i - 1].startMs));

const b168 = ctx.slBucketSeries([t(15, 1, 0), t(10, 3, 0)], 168, now);
check("168 h: baldes diários com rótulo dd/mm", b168[b168.length - 1].label === "15/10" && b168.length === 8);
check("168 h: conta por dia", b168[b168.length - 1].count === 1 && b168.some((b) => b.label === "10/10" && b.count === 1));

const b1 = ctx.slBucketSeries([t(15, 14, 17)], 1, now);
check("1 h: baldes de 5 min com HH:MM", b1.every((b) => /^\d\d:\d\d$/.test(b.label)) && b1.length >= 12 && b1.length <= 14);
check("1 h: alerta das 14:17 cai no balde 14:15", b1.find((b) => b.label === "14:15").count === 1);
check("sem timestamps -> tudo a 0", ctx.slBucketSeries([], 24, now).every((b) => b.count === 0));
check("timestamps inválidos ignorados", ctx.slBucketSeries(["lixo", null, "", t(15, 14, 1)], 24, now).reduce((a, b) => a + b.count, 0) === 1);
check("entrada que não é lista não rebenta", ctx.slBucketSeries(null, 24, now).length === 25);
check("fora da janela ignorado", ctx.slBucketSeries([t(1, 3, 0)], 24, now).every((b) => b.count === 0));
check("datas do Wazuh (+0000) contam", ctx.slBucketSeries(["2026-10-15T13:30:00.000+0000"], 48, new Date("2026-10-15T14:00:00Z").getTime()).reduce((a, b) => a + b.count, 0) === 1);

const sev = ctx.slSeverityBars({ critical: 2, high: 0, low: 5 });
check("severidades na ordem fixa Crítico -> Info", sev.rows.map((r) => r.label).join(",") === "Crítico,Alto,Médio,Baixo,Info");
check("severidades com zeros e total", sev.rows.map((r) => r.value).join(",") === "2,0,0,5,0" && sev.total === 7);
check("sem dados -> total 0", ctx.slSeverityBars(null).total === 0 && ctx.slSeverityBars({}).total === 0);

const ev = ctx.slEventBars([{ event_id: 4624, name: "Logon", count: 3 }, { event_id: 4625, name: "Logon falhado", count: 9 }, { event_id: 7, count: 1 }, { event_id: 8, name: "x", count: 0 }]);
check("eventos ordenados por contagem", ev.map((e) => e.value).join(",") === "9,3,1");
check("rótulo «id · nome»", ev[0].label === "4625 · Logon falhado");
check("sem nome usa só o id", ev[2].label === "7");
check("zeros fora da lista", ev.length === 3);
check("limite respeitado", ctx.slEventBars(Array.from({ length: 20 }, (_, i) => ({ event_id: i, name: "n", count: i + 1 })), 5).length === 5);
check("eventos inválidos -> lista vazia", ctx.slEventBars(undefined).length === 0);

check("truncar curto não muda", ctx.slTruncate("abc", 10) === "abc");
check("truncar longo põe reticências", ctx.slTruncate("abcdefghij", 5) === "abcd…");
check("truncar null -> vazio", ctx.slTruncate(null, 5) === "");
check("slHasAnyValue", ctx.slHasAnyValue([[0, 0], [0, 2]]) === true && ctx.slHasAnyValue([[0, 0], []]) === false && ctx.slHasAnyValue(null) === false);
check("aria-label sem dados", ctx.slChartAriaLabel("Alertas", []) === "Alertas: sem dados nesta janela");
check("aria-label lista e resume o resto", ctx.slChartAriaLabel("T", Array.from({ length: 8 }, (_, i) => ({ label: "a" + i, value: i }))) === "T: a0 0, a1 1, a2 2, a3 3, a4 4, a5 5 e mais 2");
if (failures.length) process.exit(1);
