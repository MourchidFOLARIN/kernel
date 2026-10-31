/**
 * Audit « chaque bouton fait quelque chose » sur /app.
 *
 * Inscrit deux comptes neufs via /rejoindre (A audite, B lui écrit pour qu'il y ait des
 * messages), puis, en desktop (1280px) et mobile (375px), recharge /app et clique
 * réellement (souris) chaque bouton / lien / onglet visible, dans plusieurs états :
 * accueil, conversation ouverte, chaque onglet, chaque boîte de dialogue.
 * ÉCHEC si un clic ne produit aucun effet visible, si l'élément est recouvert par un
 * autre (overlay), ou si une erreur console / page / réseau survient pendant le clic.
 *
 * Usage : BASE=http://<ip>:3000 [AUDIT_BROWSER=chrome|firefox] [CHROME=…] [FIREFOX=…] node tools/audit-buttons.mjs
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
const results = [];
let failures = 0;

function wire(page, bucket) {
  page.on("console", (m) => { if (m.type() === "error") bucket.push("console: " + m.text()); });
  page.on("pageerror", (e) => bucket.push("pageerror: " + e.message));
  page.on("requestfailed", (r) => {
    const u = r.url();
    if (!/\/ws$|favicon|blob:/.test(u)) bucket.push(`requestfailed: ${u} ${r.failure()?.errorText || ""}`);
  });
  page.on("response", (r) => { if (r.status() >= 400 && !r.url().includes("favicon")) bucket.push(`HTTP ${r.status()} ${r.url()}`); });
  page.on("dialog", async (d) => { bucket.native = (bucket.native || 0) + 1; await d.dismiss().catch(() => {}); });
}

/** Un navigateur isolé par utilisateur (cookies séparés, fonctionne aussi avec Firefox). */
async function register(name) {
  const b = await launch(); browsers.push(b);
  const page = await b.newPage();
  const bucket = [];
  wire(page, bucket);
  await page.goto(BASE + "/rejoindre", { waitUntil: "load" });
  await page.waitForSelector("input[name=username]");
  await page.type("input[name=username]", name);
  await page.type("input[name=email]", `${name}@exemple.fr`);
  await page.type("input[name=password]", "MotDePasse!2026");
  await Promise.all([page.waitForNavigation({ timeout: 15000 }), page.click("button[type=submit]")]);
  await page.waitForFunction(() => document.getElementById("app")?.dataset.ready === "1", { timeout: 15000 });
  return { page, bucket };
}

async function listTargets(page, scope) {
  return page.evaluate((scope) => {
    const path = (el) => {
      const parts = [];
      while (el && el.nodeType === 1 && el !== document.body) {
        if (el.id) { parts.unshift("#" + CSS.escape(el.id)); break; }
        let i = 1, s = el; while ((s = s.previousElementSibling)) if (s.tagName === el.tagName) i++;
        parts.unshift(el.tagName.toLowerCase() + ":nth-of-type(" + i + ")");
        el = el.parentElement;
      }
      return parts.join(" > ");
    };
    const rootEl = document.querySelector(scope) || document.getElementById("app");
    const els = [...rootEl.querySelectorAll("button, a[href], [role=tab], summary")];
    return els.filter((e) => {
      const r = e.getBoundingClientRect(); const cs = getComputedStyle(e);
      return r.width > 0 && r.height > 0 && cs.visibility !== "hidden" && !e.closest("[hidden]");
    }).map((e) => ({ sel: path(e), label: (e.getAttribute("aria-label") || e.textContent || e.title || e.tagName).trim().replace(/\s+/g, " ").slice(0, 42) }));
  }, scope);
}

async function snap(page) {
  return page.evaluate(() => {
    const dlg = [...document.querySelectorAll("dialog[open]")].map((d) => d.id).join(",");
    const vis = [...document.querySelectorAll("body *")].filter((e) => e.getClientRects().length).length;
    const html = document.body.innerHTML;
    let h = 0; for (let i = 0; i < html.length; i++) h = (h * 31 + html.charCodeAt(i)) | 0;
    return { url: location.href, dlg, vis, h, focus: document.activeElement?.id || document.activeElement?.tagName };
  });
}

/** Met la page dans un état donné, depuis un rechargement complet. */
async function prepare(page, st) {
  await page.goto(BASE + "/app", { waitUntil: "load" });
  await page.waitForFunction(() => document.getElementById("app")?.dataset.ready === "1", { timeout: 15000 });
  await sleep(300);
  const click = (sel) => page.$eval(sel, (e) => e.click());
  if (st === "conversation") {
    await page.evaluate(() => [...document.querySelectorAll("#conv-list .conv-row")].find((b) => b.textContent.includes("général"))?.click());
    await page.waitForFunction(() => document.querySelector("#chat-msgs .bubble"), { timeout: 8000 }).catch(() => {});
  } else if (st.startsWith("tab-")) {
    await click(`#${st}`);
    await sleep(700);
  } else if (st === "dlg-newmsg") {
    await click("#btn-new-message");
    await page.waitForFunction(() => document.querySelectorAll("#newmsg-list .member-row").length > 0, { timeout: 8000 }).catch(() => {});
  } else if (st === "dlg-group") {
    await click('[data-action="new-group"]');
    await sleep(700);
  } else if (st === "dlg-settings") {
    await click('[data-action="open-settings"]');
    await sleep(700);
  }
  await sleep(200);
}
const SCOPE = { "dlg-newmsg": "#newmsg-dlg", "dlg-group": "#group-dlg", "dlg-settings": "#settings-dlg" };

async function audit(user, viewport, st) {
  const { page, bucket } = user;
  await page.setViewport(viewport);
  await prepare(page, st);
  const targets = await listTargets(page, SCOPE[st] || "#app");
  for (const t of targets) {
    const tag = { vp: viewport.width, st, ...t };
    if (/déconnexion/i.test(t.label)) { results.push({ ...tag, status: "SKIP (déconnexion)" }); continue; }
    await prepare(page, st);
    bucket.length = 0; bucket.native = 0;
    const handle = await page.$(t.sel);
    if (!handle || !(await handle.boundingBox())) { results.push({ ...tag, status: "SKIP (absent après rechargement)" }); continue; }
    if (await handle.evaluate((e) => e.getAttribute("aria-selected") === "true" || e.getAttribute("aria-current") === "true")) { results.push({ ...tag, status: "OK (déjà actif)" }); continue; }
    await handle.evaluate((e) => e.scrollIntoView({ block: "center" }));
    const covered = await handle.evaluate((e) => {
      const r = e.getBoundingClientRect();
      const top = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
      return top && !(e === top || e.contains(top)) ? (top.id || String(top.className) || top.tagName) : null;
    });
    const before = await snap(page);
    let clickErr = null, chooser = false;
    const fc = page.waitForFileChooser ? page.waitForFileChooser({ timeout: 1200 }).then((c) => { chooser = true; return c.cancel?.(); }).catch(() => {}) : Promise.resolve();
    try {
      const box = await page.$(t.sel).then((h) => h && h.boundingBox());
      if (!box) throw new Error("élément disparu");
      await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2); // vrai clic souris aux coordonnées
    } catch (e) { clickErr = e.message; }
    await Promise.all([fc, sleep(900)]);
    let after;
    try { after = await snap(page); } catch { after = { url: "navigation" }; }
    const changed = !clickErr && (chooser || after.url !== before.url || after.dlg !== before.dlg || after.vis !== before.vis
      || after.h !== before.h || after.focus !== before.focus);
    const errs = bucket.filter((x) => !/ERR_ABORTED|NS_BINDING_ABORTED|NS_ERROR_ABORT/.test(x));
    let status = "OK";
    if (covered) status = `RECOUVERT par « ${covered} »`;
    else if (clickErr) status = "clic impossible : " + clickErr;
    else if (!changed) status = "AUCUN EFFET visible";
    if (errs.length) status = (status === "OK" ? "" : status + " | ") + "ERREURS : " + errs.join(" ; ");
    if (bucket.native) status += (status === "OK" ? "" : " | ") + "alert()/confirm() natif";
    if (!status.startsWith("OK")) failures++;
    results.push({ ...tag, status });
  }
}

const A = await register(`audit${sfx}`);
const B = await register(`voisin${sfx}`);
// B écrit dans #général pour qu'A ait des bulles « des autres » (répondre, réagir, signaler)…
await B.page.evaluate(() => [...document.querySelectorAll("#conv-list .conv-row")].find((b) => b.textContent.includes("général"))?.click());
await B.page.waitForSelector("#chat-input:not([disabled])");
await B.page.type("#chat-input", `Salut, je suis voisin${sfx}`);
await B.page.keyboard.press("Enter");
await sleep(800);
// …et A écrit aussi (bulles « à moi » : modifier, supprimer).
await prepare(A.page, "conversation");
await A.page.type("#chat-input", "Bonjour tout le monde");
await A.page.keyboard.press("Enter");
await sleep(800);

const STATES = ["home", "conversation", "tab-rooms", "tab-people", "tab-requests", "dlg-newmsg", "dlg-group", "dlg-settings"];
for (const vp of [{ width: 1280, height: 850 }, { width: 375, height: 740, isMobile: true, hasTouch: true }]) {
  for (const st of STATES) await audit(A, vp, st);
}
const seen = new Set();
for (const r of results) {
  const key = `${r.vp}|${r.st}|${r.label}|${r.status}`;
  if (seen.has(key)) continue; seen.add(key);
  console.log(`${r.status.startsWith("OK") || r.status.startsWith("SKIP") ? "✔" : "✘"} [${r.vp}px · ${r.st}] ${r.label}  →  ${r.status}`);
}
console.log(`\n${WHICH} : ${results.length} clics testés, ${failures} problème(s)`);
for (const b of browsers) await b.close();
process.exit(failures ? 1 : 0);
