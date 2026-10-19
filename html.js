// html.js — HTML seguro por omissão (W7.1, E4). Script clássico, prefixo `htm`
// (a tag template chama-se `htmlT` e o marcador `htmlRaw`, como pedido).
// Sem DOM no topo: testável em node:vm (scripts/test_html.cjs).
//
// Uso:
//   el.innerHTML = htmString(htmlT`<td title="${nome}">${nome}</td>`);
//   htmlT`<ul>${itens.map(i => htmlT`<li>${i}</li>`)}</ul>`   // arrays e aninhados
//   htmlT`<span>${htmlRaw(svgJaSeguro)}</span>`               // HTML já seguro
//
// Regras: as partes literais do template são código do programador (de
// confiança); TODA a interpolação é escapada (& < > " ' `) exceto valores
// SafeHtml (resultado de htmlT/htmlRaw). null/undefined/false -> "".
// Interpolar fora de texto ou de valor de atributo entre aspas (nome de
// atributo, <script>, href="javascript:…") continua a ser da responsabilidade
// de quem escreve o template.

class HtmSafe {
  constructor(s) { this.htmSafe = true; this.value = String(s); }
  toString() { return this.value; }
}

function htmEscape(v) {
  return String(v)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;")
    .replace(/`/g, "&#96;");
}

function htmIsSafe(v) {
  return v instanceof HtmSafe;
}

// Marca HTML JÁ seguro (ex.: SVG de ícone do próprio código). Nunca com texto
// vindo do backend ou do utilizador.
function htmlRaw(s) {
  return new HtmSafe(s === null || s === undefined ? "" : s);
}

function htmPart(v) {
  if (v === null || v === undefined || v === false) return "";
  if (htmIsSafe(v)) return v.value;
  if (Array.isArray(v)) return v.map(htmPart).join("");
  return htmEscape(v);
}

// Tag template: devolve um SafeHtml.
function htmlT(strings, ...values) {
  let out = strings[0];
  for (let i = 0; i < values.length; i++) out += htmPart(values[i]) + strings[i + 1];
  return new HtmSafe(out);
}

// Texto HTML pronto a atribuir a innerHTML. Aceita SafeHtml; qualquer outra
// coisa é ESCAPADA (nunca confiada): htmString("<b>") dá "&lt;b&gt;".
function htmString(v) {
  return htmPart(v);
}

// Atribui a innerHTML apenas SafeHtml; outro tipo é um erro de programação.
function htmRender(el, safe) {
  if (!el) return null;
  if (!htmIsSafe(safe)) throw new TypeError("htmRender: precisa de htmlT`…` ou htmlRaw()");
  el.innerHTML = safe.value;
  return el;
}
