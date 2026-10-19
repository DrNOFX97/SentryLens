"use strict";
// Teste Node de html.js em node:vm. Uso: node test_html.cjs <html.js>
const fs = require("node:fs");
const vm = require("node:vm");
const failures = [];
function check(label, cond) { console.log(`[${cond ? "OK   " : "FALHOU"}] ${label}`); if (!cond) failures.push(label); }

const ctx = vm.createContext({ console });
try {
  vm.runInContext(fs.readFileSync(process.argv[2], "utf8"), ctx, { filename: process.argv[2] });
  check("html.js carrega sem window nem DOM", true);
} catch (e) { check(`carregamento: ${e && e.message}`, false); process.exit(1); }
const T = (v) => { ctx.v = v; return vm.runInContext("htmString(htmlT`<td>${v}</td>`)", ctx); };
const A = (v) => { ctx.v = v; return vm.runInContext('htmString(htmlT`<a title="${v}">x</a>`)', ctx); };

check("texto simples intacto", T("olá") === "<td>olá</td>");
check("escapa <script>", T("<script>alert(1)</script>") === "<td>&lt;script&gt;alert(1)&lt;/script&gt;</td>");
check("escapa & primeiro (sem duplo escape)", T("a&b") === "<td>a&amp;b</td>");
check("&#39; vindo do utilizador fica literal (&amp;#39;)", T("&#39;") === "<td>&amp;#39;</td>");
check("aspa simples -> &#39;", T("'") === "<td>&#39;</td>");
check("aspa dupla -> &quot;", T('"') === "<td>&quot;</td>");
check("backtick escapado", T("`") === "<td>&#96;</td>");

const a1 = A(`x" onmouseover="alert(1)`);
check("atributo: não consegue sair das aspas", a1 === '<a title="x&quot; onmouseover=&quot;alert(1)">x</a>');
const a2 = A(`x' onclick='alert(1)`);
check("atributo com aspas simples: nenhuma ' literal no valor", a2 === '<a title="x&#39; onclick=&#39;alert(1)">x</a>');
check("payload com &#39; num atributo continua inerte", A("&#39; onclick=&#39;x") === '<a title="&amp;#39; onclick=&amp;#39;x">x</a>');
check("<img onerror> neutralizado", !T("<img src=x onerror=alert(1)>").includes("<img"));

check("null/undefined/false -> vazio", T(null) === "<td></td>" && T(undefined) === "<td></td>" && T(false) === "<td></td>");
check("0 é escrito (não é «sem valor»)", T(0) === "<td>0</td>");
check("número", T(42) === "<td>42</td>");
check("objeto não-seguro é escapado", T({ toString() { return "<b>"; } }) === "<td>&lt;b&gt;</td>");

check("htmlT aninhado não é escapado duas vezes", vm.runInContext("htmString(htmlT`<ul>${htmlT`<li>a&b</li>`}</ul>`)", ctx) === "<ul><li>a&b</li></ul>");
ctx.itens = ["<b>", "a&b"];
check("array de itens: cada um escapado e juntos", vm.runInContext("htmString(htmlT`<ul>${itens.map(i => htmlT`<li>${i}</li>`)}</ul>`)", ctx) === "<ul><li>&lt;b&gt;</li><li>a&amp;b</li></ul>");
check("array de strings cruas é escapado", vm.runInContext("htmString(htmlT`${itens}`)", ctx) === "&lt;b&gt;a&amp;b");
check("htmlRaw não escapa", vm.runInContext("htmString(htmlT`<i>${htmlRaw('<svg/>')}</i>`)", ctx) === "<i><svg/></i>");
check("htmlRaw(null) -> vazio", vm.runInContext("htmString(htmlRaw(null))", ctx) === "");
check("string solta em htmString é escapada, nunca confiada", vm.runInContext("htmString('<b>x</b>')", ctx) === "&lt;b&gt;x&lt;/b&gt;");
check("htmIsSafe distingue", vm.runInContext("htmIsSafe(htmlT`a`) && htmIsSafe(htmlRaw('a')) && !htmIsSafe('a') && !htmIsSafe({htmSafe:true,value:'<x>'})", ctx));
ctx.f = { htmSafe: true, value: "<script>" };
check("objeto forjado {htmSafe:true} não passa por seguro", vm.runInContext("htmString(htmlT`${f}`)", ctx).includes("<script>") === false);

ctx.el = { innerHTML: "" };
vm.runInContext("htmRender(el, htmlT`<p>${'<x>'}</p>`)", ctx);
check("htmRender escreve innerHTML do SafeHtml", ctx.el.innerHTML === "<p>&lt;x&gt;</p>");
let threw = false;
try { vm.runInContext("htmRender(el, '<script>')", ctx); } catch (e) { threw = true; }
check("htmRender recusa string solta", threw && ctx.el.innerHTML === "<p>&lt;x&gt;</p>");
check("htmRender(null) é inofensivo", vm.runInContext("htmRender(null, htmlT`a`)", ctx) === null);

process.exit(failures.length ? 1 : 0);
