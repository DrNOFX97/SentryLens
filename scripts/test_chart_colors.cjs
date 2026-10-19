"use strict";
// Teste node:vm dos helpers de cor de ui_helpers.js (slCssToken, slColorAlpha, ...).
const fs = require("node:fs");
const vm = require("node:vm");
const failures = [];
function check(l, c) { console.log(`[${c ? "OK   " : "FALHOU"}] ${l}`); if (!c) failures.push(l); }
const ctx = vm.createContext({});
vm.runInContext(fs.readFileSync(process.argv[2], "utf8"), ctx);
const style = { getPropertyValue: (n) => (n === "--accent" ? "  #0a7285 " : "") };
check("token existente é aparado", ctx.slCssToken(style, "--accent") === "#0a7285");
check("token em falta -> vazio", ctx.slCssToken(style, "--x") === "");
check("sem style -> vazio", ctx.slCssToken(null, "--x") === "");
check("alpha em #rrggbb", ctx.slColorAlpha("#ff0000", 0.5) === "color(srgb 1 0 0 / 0.5)");
check("alpha em #rgb", ctx.slColorAlpha("#fff", 1) === "color(srgb 1 1 1 / 1)");
check("formato desconhecido fica igual", ctx.slColorAlpha("red", 0.5) === "red");
check("alpha inválido fica igual", ctx.slColorAlpha("#ff0000", 2) === "#ff0000");
check("severidade -> token", ctx.slSeverityToken("high") === "--sev-high");
check("severidade desconhecida -> info", ctx.slSeverityToken("zzz") === "--sev-info");
check("categoria 0 -> cat-1", ctx.slCategoryToken(0) === "--cat-1");
check("categoria 8 volta a cat-1", ctx.slCategoryToken(8) === "--cat-1");
check("categoria inválida -> cat-1", ctx.slCategoryToken(-2) === "--cat-1");
if (failures.length) process.exit(1);
