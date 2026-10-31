/**
 * E2E « usage réel » : 3 comptes créés via /rejoindre, 3 navigateurs isolés (C en mobile 375px).
 *  - A : « Nouveau message » → cherche B par pseudo → clic → le curseur est dans la saisie → Entrée.
 *  - B reçoit en temps réel (badge non lu), ouvre, répond avec le bouton « Envoyer ».
 *  - Maj+Entrée = retour à la ligne (pas d'envoi).
 *  - C (mobile) : onglet Membres → recherche A → clic → envoie ; A reçoit.
 *  - #général : un message atteint les 3 ; rechargement complet = historique conservé.
 *  - Erreur visible : B bloque A → l'envoi de A affiche un message d'erreur clair.
 *  - Coupure WebSocket → bandeau, reconnexion automatique.
 *
 * Usage : BASE=http://<ip>:3000 [AUDIT_BROWSER=chrome|firefox] [CHROME=…] [FIREFOX=…] node tools/e2e-multiuser.mjs
 */
import puppeteer from "puppeteer-core";

const BASE = process.env.BASE || "http://127.0.0.1:3000";
const WHICH = process.env.AUDIT_BROWSER || "chrome";
const sfx = Date.now().toString(36).slice(-5);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const launch = () => WHICH === "firefox"
  ? puppeteer.launch({ browser: "firefox", executablePath: process.env.FIREFOX, headless: true })
  : puppeteer.launch({ executablePath: process.env.CHROME || "/usr/bin/google-chrome", headless: "new", args: ["--no-sandbox"] });
const browsers = [];
const jsErrors = [];
let fails = 0;
const check = (cond, label) => { console.log(`${cond ? "✔" : "✘"} ${label}`); if (!cond) fails++; };

async function register(name, mobile = false) {
  const b = await launch(); browsers.push(b);
  const p = await b.newPage();
  await p.setViewport(mobile ? { width: 375, height: 740, isMobile: true, hasTouch: true } : { width: 1280, height: 850 });
  p.on("pageerror", (e) => jsErrors.push(`${name}: ${e.message}`));
  p.on("console", (m) => { if (m.type() === "error" && !/favicon/.test(m.text())) jsErrors.push(`${name} console: ${m.text()}`); });
  await p.goto(BASE + "/rejoindre", { waitUntil: "load" });
  await p.waitForSelector("input[name=username]");
  await p.type("input[name=username]", name);
  await p.type("input[name=email]", `${name}@exemple.fr`);
  await p.type("input[name=password]", "MotDePasse!2026");
  await Promise.all([p.waitForNavigation({ timeout: 15000 }), p.click("button[type=submit]")]);
  await p.waitForFunction(() => document.getElementById("app")?.dataset.ready === "1", { timeout: 15000 });
  return p;
}
const bodies = (p) => p.$$eval("#chat-msgs .bubble-body", (e) => e.map((x) => x.textContent.trim()));
const waitText = (p, text, ms = 6000) => p.waitForFunction((t) => [...document.querySelectorAll("#chat-msgs .bubble-body")]
  .some((x) => x.textContent.includes(t)), { timeout: ms }, text).then(() => true).catch(() => false);
const visible = (p, sel) => p.$eval(sel, (e) => !!e.getClientRects().length && !e.closest("[hidden]")).catch(() => false);
async function back(p) { if (await visible(p, '[data-action="back"]')) { await p.click('[data-action="back"]'); await sleep(300); } }
async function openConvNamed(p, name) {
  await back(p);
  await p.evaluate((n) => [...document.querySelectorAll("#conv-list .conv-row")].find((b) => b.textContent.includes(n))?.click(), name);
  await sleep(900);
}

const names = { a: `ana${sfx}`, b: `ben${sfx}`, c: `chloe${sfx}` };
const A = await register(names.a);
const B = await register(names.b);
const C = await register(names.c, true);
check(A.url().endsWith("/app") && C.url().endsWith("/app"), "inscription → connecté automatiquement sur /app");

// 1) A : « Nouveau message » → recherche B → clic (vrais clics souris)
await A.click("#btn-new-message");
await A.waitForSelector("#newmsg-dlg[open]", { timeout: 4000 }).catch(() => {});
check(await visible(A, "#newmsg-dlg"), "« Nouveau message » ouvre le sélecteur de destinataire");
await A.waitForFunction(() => document.querySelectorAll("#newmsg-list .member-row").length >= 2, { timeout: 6000 }).catch(() => {});
const total = await A.$$eval("#newmsg-list .member-row", (e) => e.map((x) => x.textContent));
check(total.some((t) => t.includes(names.b)) && total.some((t) => t.includes(names.c)) && total.some((t) => t.includes("alice"))
  && !total.some((t) => t.includes("@" + names.a)), `le sélecteur liste TOUS les membres inscrits sauf soi (${total.length})`);
await A.type("#newmsg-search", names.b.slice(0, 6));
await sleep(200);
const filtered = await A.$$eval("#newmsg-list .member-row", (e) => e.map((x) => x.textContent));
check(filtered.length >= 1 && filtered.every((t) => t.includes(names.b.slice(0, 6))), "filtrage instantané par pseudo");
await A.click(`#newmsg-list .member-row[data-user-id]`);
await A.waitForFunction(() => !document.getElementById("chat").hidden, { timeout: 6000 }).catch(() => {});
check(await A.waitForFunction(() => document.activeElement?.id === "chat-input", { timeout: 3000 }).then(() => true).catch(() => false), "clic sur le membre → conversation ouverte, curseur dans la saisie");
check((await A.$eval("#chat-title", (e) => e.textContent)).length > 0, "en-tête de conversation renseigné");

// 2) Entrée envoie, Maj+Entrée = nouvelle ligne
await A.type("#chat-input", "ligne 1");
await A.keyboard.down("Shift"); await A.keyboard.press("Enter"); await A.keyboard.up("Shift");
await A.type("#chat-input", "ligne 2");
check((await A.$eval("#chat-input", (e) => e.value)) === "ligne 1\nligne 2", "Maj+Entrée insère un retour à la ligne sans envoyer");
await A.keyboard.press("Enter");
check(await waitText(A, "ligne 1", 1500), "le message apparaît tout de suite chez l'expéditeur");
check((await A.$eval("#chat-input", (e) => e.value)) === "", "la zone de saisie est vidée après l'envoi");

// 3) B reçoit en temps réel, ouvre, répond avec le bouton Envoyer
await B.waitForFunction((n) => [...document.querySelectorAll("#conv-list .conv-row")].some((r) => r.textContent.includes(n) && r.querySelector(".badge-unread")),
  { timeout: 6000 }, names.a).then(() => check(true, "B : la discussion arrive en direct avec un badge non lu"))
  .catch(() => check(false, "B : la discussion arrive en direct avec un badge non lu"));
await B.evaluate((n) => [...document.querySelectorAll("#conv-list .conv-row")].find((r) => r.textContent.includes(n))?.scrollIntoView(), names.a);
const rowB = await B.evaluateHandle((n) => [...document.querySelectorAll("#conv-list .conv-row")].find((r) => r.textContent.includes(n)), names.a);
await rowB.asElement().click();
check(await waitText(B, "ligne 2"), "B lit le message de A");
await B.type("#chat-input", "Salut A, bien reçu !");
await B.click("#chat-send");
check(await waitText(A, "bien reçu"), "A reçoit la réponse de B en temps réel");
await sleep(800);
check(await A.$$eval(".bubble.me .receipt", (e) => e.some((x) => x.classList.contains("read"))), "accusé de lecture « lu » chez A");

// 4) C (mobile 375px) : onglet Membres → recherche A → touche → envoie
await C.click("#tab-people");
await C.waitForFunction(() => document.querySelectorAll("#people-list .member-row").length > 0, { timeout: 6000 }).catch(() => {});
await C.type("#people-search", names.a);
await sleep(200);
check(await C.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), "mobile : aucune largeur qui déborde de l'écran");
await C.click("#people-list .member-row");
await C.waitForFunction(() => !document.getElementById("chat").hidden, { timeout: 6000 }).catch(() => {});
check(await visible(C, "#chat-input") && !(await visible(C, ".kside")), "mobile : la conversation s'affiche en plein écran");
await C.type("#chat-input", "coucou depuis mon téléphone");
await C.click("#chat-send");
check(await waitText(C, "téléphone", 1500), "mobile : message affiché immédiatement");
await back(A);
await A.waitForFunction((n) => [...document.querySelectorAll("#conv-list .conv-row")].some((r) => r.textContent.includes(n)), { timeout: 6000 }, names.c).catch(() => {});
await openConvNamed(A, names.c);
check(await waitText(A, "téléphone"), "A reçoit le message de C (mobile)");

// 5) #général : un message de B atteint A et C
await openConvNamed(A, "général"); await openConvNamed(C, "général"); await openConvNamed(B, "général");
await B.type("#chat-input", `annonce ${sfx}`); await B.keyboard.press("Enter");
check(await waitText(A, `annonce ${sfx}`) && await waitText(C, `annonce ${sfx}`), "#général : message reçu par tous en temps réel");
check((await A.$$eval(".bubble-author", (e) => e.map((x) => x.textContent))).some((t) => t.includes(names.b)), "#général : nom de l'auteur affiché");

// 6) Rechargement complet : l'historique est conservé
await A.reload({ waitUntil: "load" });
await A.waitForFunction(() => document.getElementById("app")?.dataset.ready === "1", { timeout: 15000 });
await openConvNamed(A, names.b);
check(await waitText(A, "bien reçu"), "après rechargement complet, l'historique est là");

// 7) Erreur claire : B bloque A, puis A essaie d'écrire à B
await back(B);
await B.click("#tab-people"); await sleep(500);
await B.type("#people-search", names.a); await sleep(200);
await B.click('#people-list [data-action="block"]');
await B.waitForSelector("#ask-dlg[open]", { timeout: 3000 }).catch(() => {});
await B.click("#ask-ok");
await B.waitForFunction(() => [...document.querySelectorAll(".toast")].some((t) => /bloqué/i.test(t.textContent)), { timeout: 4000 })
  .then(() => check(true, "blocage confirmé par un toast")).catch(() => check(false, "blocage confirmé par un toast"));
await A.type("#chat-input", "tu es là ?"); await A.keyboard.press("Enter");
await A.waitForFunction(() => document.querySelector(".toast") && document.querySelector(".bubble.failed"), { timeout: 6000 })
  .then(() => check(true, "envoi refusé → toast d'erreur + bulle « Non envoyé — réessayer »"))
  .catch(() => check(false, "envoi refusé → toast d'erreur + bulle « Non envoyé — réessayer »"));

// 8) Coupure WebSocket → bandeau puis reconnexion
await C.evaluate(() => window.KernelApp.ws.close());
await sleep(300);
check(await visible(C, "#conn-status") || await C.evaluate(() => !document.getElementById("conn-status").hidden), "coupure : bandeau « Connexion perdue » visible");
await C.waitForFunction(() => document.getElementById("conn-status").hidden, { timeout: 8000 })
  .then(() => check(true, "reconnexion automatique")).catch(() => check(false, "reconnexion automatique"));

check(!jsErrors.length, "aucune erreur JavaScript / console" + (jsErrors.length ? " : " + jsErrors.join(" | ") : ""));
for (const b of browsers) await b.close();
console.log(fails ? `\n${WHICH} : ${fails} échec(s)` : `\n${WHICH} : tout est OK`);
process.exit(fails ? 1 : 0);
