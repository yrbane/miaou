## Stack cœur (simple, ambitieuse, belle)

1. Voici une version **adaptée pour un site 100 % local/offline** (aucun appel réseau en prod, aucun CDN, pas de déploiement cloud). 

---

# Stack cœur (local & offline)

1. **Astro (SSG)** – génère uniquement des fichiers statiques. Aucune requête réseau en prod si on reste sur du contenu local.
2. **Tailwind CSS** – compilé localement via le plugin Astro, pas de CDN.
3. **Motion** – animations micro‑interactions, packagée via npm (aucune ressource externe).
4. **(Option) Spline / Rive** – intégrés **sans CDN** en npm ou en “vendorisé” dans `public/vendor/` pour rester offline.
5. **Aucun CMS distant** – contenu en Markdown/Collections Astro, modifiable localement.
6. **Aucun hébergeur** – on ouvre `dist/` avec un petit serveur de fichiers local (ou directement via `file://` si tout est bien relatif).

*Pourquoi cette combo ?*
Tout est packagé/servi en local : HTML/CSS/JS, polices, images, animations. Zéro dépendance réseau au runtime.

---

## Bootstrap local en 10 min

```bash
# 1) Projet
npm create astro@latest my-site -- --template basics
cd my-site
npm install

# 2) Tailwind (local)
npx astro add tailwind

# 3) Animations (local)
npm i motion

# 4) (Option) Rive & Spline – sans CDN (voir plus bas pour l’usage)
npm i @rive-app/webgl @splinetool/viewer

# 5) Dev
npm run dev

# 6) Build statique
npm run build

# 7) Prévisualisation 100% locale (sans internet)
npm run preview   # lance un petit serveur local qui sert ./dist
# OU npx http-server ./dist (si tu préfères) – mais sans sortir sur le réseau
```

> Astuce : pour un usage « double‑clic » via `file://`, garde des **URLs relatives** (voir section “Liens & assets relatifs”).

---

## Arborescence

```
my-site/
  ├─ public/                 # assets statiques (fonts, favicons, .riv, .glb, vendor JS…)
  │  └─ vendor/              # (option) copies locales de libs (si tu ne veux pas npm)
  ├─ src/
  │  ├─ content/
  │  │  └─ config.ts         # schémas typés (Astro Content)
  │  ├─ components/
  │  │  ├─ Hero.astro
  │  │  ├─ RiveBlock.astro   # (option)
  │  │  └─ SplineBlock.astro # (option)
  │  └─ pages/
  │     └─ index.astro
  └─ astro.config.mjs
```

---

## Typage strict & contenu local

**`src/content/config.ts`**

```ts
import { z, defineCollection } from "astro:content";

const pages = defineCollection({
  type: "content",
  schema: z.object({
    title: z.string().min(1),
    description: z.string().min(1),
    heroTagline: z.string().min(1),
    published: z.boolean().default(true),
    order: z.number().default(0),
  }),
});

export const collections = { pages };
```

Stocke tes contenus en Markdown/MDX dans `src/content/pages/` – tout est compilé à la build, pas de réseau.

---

## Page d’accueil (Astro + Tailwind + Motion, zéro CDN)

**`src/pages/index.astro`**

```astro
---
import Hero from "../components/Hero.astro";
---

<html lang="fr">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Local‑Only Static Site</title>

    <!-- CSP stricte : aucun domaine externe -->
    <meta http-equiv="Content-Security-Policy"
      content="default-src 'self'; img-src 'self' data: blob:; script-src 'self'; style-src 'self'; font-src 'self' data:; connect-src 'self'; object-src 'none'">
    <!-- Base relative pour un usage via file:// -->
    <base href="./">
  </head>

  <body class="min-h-screen bg-neutral-950 text-neutral-100">
    <Hero />

    <!-- Motion packagé localement via npm (aucun CDN) -->
    <script type="module">
      import { animate } from "/node_modules/motion/dist/index.mjs";
      const prefersReduced =
        window.matchMedia("(prefers-reduced-motion: reduce)").matches;
      if (!prefersReduced) {
        animate(".cta-pulse", { scale: [1, 1.04, 1] }, { duration: 1.1, repeat: Infinity });
      }
    </script>
  </body>
</html>
```

**`src/components/Hero.astro`**

```astro
<section class="relative isolate overflow-hidden px-6 py-24 md:px-8">
  <div class="mx-auto max-w-3xl">
    <h1 class="text-balance text-5xl font-extrabold tracking-tight md:text-7xl">
      Be bold. Ship static. Stay offline.
    </h1>
    <p class="mt-6 text-lg text-neutral-300">
      Tout packagé en local. Zéro CDN. Zéro requête réseau en prod.
    </p>
    <div class="mt-10 flex items-center gap-4">
      <a href="#start" class="cta-pulse inline-flex items-center rounded-md px-6 py-3 text-base font-semibold ring-1 ring-white/20 hover:bg-white/10">
        Démarrer
      </a>
      <a href="#demo" class="text-sm opacity-80 hover:opacity-100 underline">Voir la démo</a>
    </div>
  </div>
</section>
```

---

## “Wow factor” offline (Spline & Rive sans CDN)

### Option A – via npm (recommandé)

**Spline (web‑component packagé)**

```astro
---
// Dans un composant .astro
import " @splinetool/viewer"; // enregistre <spline-viewer> sans CDN
---
<spline-viewer
  url="/3d/scene.splinecode"    /* fichier local exporté depuis Spline */
  loading="lazy"
  aria-label="3D scene"
  style="width:100%;height:500px;border-radius:1rem;overflow:hidden"
/>
```

> Exporte ta scène en `.splinecode` et place‑la dans `public/3d/scene.splinecode`.

**Rive (runtime webgl packagé)**

```astro
<canvas id="rive-logo" width="320" height="96" aria-label="Animated logo"></canvas>
<script type="module">
  import * as rive from "/node_modules/@rive-app/webgl/dist/rive.mjs";
  new rive.Rive({
    src: "/animations/logo.riv",           // fichier local placé dans public/animations/
    canvas: document.getElementById("rive-logo"),
    autoplay: true
  });
</script>
```

### Option B – “vendoriser” les scripts (sans npm)

1. Télécharge les bundles minifiés (une fois, en dev) et copie‑les dans `public/vendor/`.
2. Référence‑les en local :

   ```html
   <script type="module" src="/vendor/spline-viewer.js"></script>
   <script type="module" src="/vendor/rive-webgl.mjs"></script>
   ```

---

## Polices & images 100 % locales

* Place tes **polices variables** dans `public/fonts/` et déclare‑les via `@font-face` (URLs relatives).
* Utilise Astro `<Image />` pour générer des images optimisées à la build, toutes stockées en local.
* Évite toute URL absolue (ne commence pas par `/` si tu vises `file://`), utilise des **chemins relatifs** (`./`, `../`).

---

## Liens & assets relatifs (important pour `file://`)

* Ajoute `<base href="./">` dans `<head>` (comme ci‑dessus).
* Évite les chemins absolus `/…` dans tes imports/URLs ; préfère `./assets/…`.
* Dans `astro.config.mjs`, force un build simple sans préfixe CDN :

**`astro.config.mjs`**

```js
import { defineConfig } from "astro/config";

export default defineConfig({
  output: "static",
  trailingSlash: "always",     // des dossiers avec index.html -> mieux pour file://
  build: {
    assets: "_astro",          // par défaut, packagé localement dans dist/_astro
    assetsPrefix: undefined,   // aucun CDN
  },
  // Pas de "site" ni de "base" pointant sur un domaine externe
});
```

---

## Sécurité & offline strict

* **CSP** (exemple en meta tag) : `default-src 'self'; img-src 'self' data: blob:; script-src 'self'; style-src 'self'; font-src 'self' data:; connect-src 'self'; object-src 'none'`
* **Aucune analytics** ni pixel distant.
* **Dépendances** : tout installé via npm et packagé au build.

---

## Ce qu’on **retire** par rapport à la version cloud

* ❌ Cloudflare Pages, DNS, previews distants
* ❌ Decap CMS (option Git UI distante)
* ✅ Contenu local (Markdown/MDX) + build Astro
* ✅ Spline/Rive packagés sans CDN

---

## Check‑list qualité (offline)

* **Perf** : images optimisées à la build, polices locales (`preload`).
* **A11y** : `aria-label` sur 3D/anim, fallback si `prefers-reduced-motion`.
* **SEO (local)** : title/description par page (utile si un jour tu mets en ligne).
* **Tests offline** : coupe le Wi‑Fi, lance `npm run preview`, valide qu’aucune requête externe n’apparaît dans l’onglet *Network*.

---

## Plan d’exécution (1 journée, focus local)

1. **Matin** – Scaffold Astro, Tailwind, contenu Markdown, Hero.
2. **Début aprem** – Motion local, assets & polices locales, chemins relatifs.
3. **Fin aprem** – Intégration Spline/Rive via npm, CSP stricte, audit *Network* hors‑ligne.
4. **Build** – `npm run build` → ouvre `dist/` via `npm run preview` (ou double‑clic si tout est relatif).
