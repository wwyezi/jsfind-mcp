// A Vite-built entry bundle: the chunk map names every lazily-loaded asset,
// and the dynamic-loading forms below are what actually ship in the wild.
const __vite__mapDeps = (i, m, fn) => [(i[0][1], fn)];
__vite__mapDeps([
  "assets/User-a1b2c3d4.js",
  "assets/Order-e5f6a7b8.js",
  "assets/QrCode-09182736.js"
], 0);

const Load = () => import(/* __vitePreload */ "./vendor-lib.js");
const lazy = () => import("./views/Report.js");
const tpl = () => import(`./locales/${lang}.js`);
const mods = import.meta.glob("./modules/*.js");
const eager = import.meta.globEager("./pages/**/*.vue");

const hashWorker = new Worker(
  new URL("./worker/hashWorker.js", import.meta.url), { type: "module" }
);
const plainWorker = new Worker("/static/plain-worker.js");

// classic worker, cross-origin
importScripts("https://cdn.example.com/legacy-worker.js");

// an interface hidden behind the lazy route
async function loadReport(params) {
  const res = await fetch(API + "/report/detail", { params });
  return res.json();
}
const API = "https://api.example.com/v3";
