import puppeteer from "puppeteer-core";
const B = process.env.BASE || "http://127.0.0.1:3000";
const browser = await puppeteer.launch({ executablePath: "/usr/bin/google-chrome", headless: "new", args: ["--no-sandbox"] });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function user(name, pw) {
  const ctx = await browser.createBrowserContext();
  const p = await ctx.newPage();
  p.on("pageerror", (e) => console.log(name, "PAGEERR", e.message));
  await p.goto(B + "/connexion");
  await p.type("input[name=username]", name); await p.type("input[name=password]", pw);
  await Promise.all([p.waitForNavigation(), p.click("button[type=submit]")]);
  return { ctx, p };
}
const call = (p, url, method, body) => p.evaluate(async (url, method, body) => {
  const t = document.querySelector('meta[name="csrf-token"]').content;
  const r = await fetch(url, { method, headers: { "Content-Type": "application/json", "X-CSRF-Token": t }, body: body && JSON.stringify(body) });
  return r.json();
}, url, method, body);
async function openConv(p, who) {
  await p.goto(B + "/app"); await p.waitForFunction(() => document.getElementById("app")?.dataset.ready === "1", { timeout: 15000 });
  await p.evaluate((w) => [...document.querySelectorAll("#conv-list .conv-row")].find((r) => r.textContent.includes(w))?.click(), who); await sleep(1500);
}
async function send(p, text) { await p.type("#chat-input", text); await p.click("#chat-send"); await sleep(1500); }
const bubbles = (p) => p.$$eval("#chat-msgs .bubble-body", (b) => b.map((x) => x.textContent.trim()));

const A = await user("alice", "Alice123!"), Bo = await user("bob", "Bob123!"), Ad = await user("admin", "Admin123!");
await Ad.p.goto(B + "/admin");
const bob = (await call(A.p, "/api/users/directory?q=bob", "GET")).find((u) => u.username === "bob");
await call(A.p, "/api/conversations/dm", "POST", { user_id: bob.id });
await call(Ad.p, "/api/admin/demo", "PUT", { algo: "AES-GCM", key_distribution: "broadcast" });
await openConv(A.p, "Bob"); await openConv(Bo.p, "Alice");

await send(A.p, "msg broadcast");
console.log("1 broadcast bob:", (await bubbles(Bo.p)).at(-1));

await call(Ad.p, "/api/admin/demo", "PUT", { key_distribution: "password" }); await sleep(1000);
console.log("2 secret bar visible alice:", await A.p.$eval("#conv-secret", (e) => !e.hidden));
for (const u of [A, Bo]) { await u.p.type("#conv-secret-input", "hunter2"); await u.p.click("#conv-secret-form button"); }
await sleep(4000);
await send(A.p, "msg password");
console.log("2 password bob:", (await bubbles(Bo.p)).at(-1));

await call(Ad.p, "/api/admin/demo", "PUT", { key_distribution: "x25519", algo: "ChaCha20-Poly1305" }); await sleep(1500);
await send(A.p, "msg ecdh");
console.log("3 x25519 bob:", (await bubbles(Bo.p)).at(-1));
await send(Bo.p, "réponse ecdh");
console.log("3 x25519 alice:", (await bubbles(A.p)).at(-1));

console.log("coulisses alice:", (await A.p.$$(".coulisses")).length, "| refresh bob history:");
await openConv(Bo.p, "Alice"); console.log("  ", await bubbles(Bo.p));

const Bo2 = await user("bob", "Bob123!"); // nouvel appareil (IndexedDB vide)
await openConv(Bo2.p, "Alice"); console.log("new device bob:", await bubbles(Bo2.p));

await call(Ad.p, "/api/admin/demo", "PUT", { key_distribution: "broadcast", algo: "AES-GCM" });
await openConv(Ad.p, "général");
console.log("coulisses admin (#général):", (await Ad.p.$$(".coulisses")).length);
await browser.close();
