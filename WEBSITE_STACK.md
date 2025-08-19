## Stack cœur (simple, ambitieuse, belle)

1. **Astro (SSG + “islands”)** – génère du HTML statique ultra‑rapide et n’hydrate que les petites zones interactives (“islands”). Parfait pour de la beauté sans JS inutile. ([Astro Docs][1])
2. **Tailwind CSS** – styling express, design system en utilitaires, responsive instantané. ([Tailwind CSS][2])
3. **Motion (ex Motion One)** – micro‑interactions fluides et modernes, footprint minime (Web Animations API). ([Motion][3], [npm][4])
4. **Spline Viewer (option “wow 3D”)** – embarque une scène 3D web composant `<spline-viewer>` en un tag. ([Spline Docs][5])
5. **Rive Web Runtime (option “micro‑anim” vectorielles)** – animations interactives ultra‑propres, contrôlables en JS/TS. ([Rive][6])
6. **Decap CMS (ex Netlify CMS, Git‑based, optionnel)** – UI d’édition simple sans backend; plug‑and‑play avec Astro. ([Decap CMS][7], [Astro Docs][8])
7. **Cloudflare Pages** – déploiement/preview CI ultra‑rapide, CDN global, parfait pour un site 100% statique. ([Cloudflare Docs][9])

**Pourquoi cette combo ?**

* **Ultra‑vite** à produire : Astro + Tailwind accélèrent la mise en page; tu gardes l’interactivité ciblée via des islands. ([Astro Docs][1], [Tailwind CSS][2])
* **Disruptif visuellement** : Spline (3D) et Rive (anim vectorielles) se plug en 2 balises. ([Spline Docs][5], [Rive][6])
* **Perf & SEO** : rendu statique par défaut, JS minimum; CDN Pages. ([Astro Docs][1], [Cloudflare Docs][9])

---

## Bootstrap en 10 min

```bash
# 1) Projet
npm create astro@latest my-site -- --template basics
cd my-site
npm install

# 2) Tailwind
npx astro add tailwind  # génère config & wiring

# 3) Animations
npm i motion            # Motion (ex Motion One)

# 4) (Option) Rive runtime + Spline viewer (via CDN dans la page)
# rien à installer si tu utilises <script src="..."> côté client

# 5) Dev
npm run dev
```

Déploiement : connecte le repo à **Cloudflare Pages** (Git integration) ou upload de l’artefact `dist/`; previews par commit inclus. ([Cloudflare Docs][10])

---

## Arborescence proposée

```
my-site/
  ├─ public/                # assets statiques (fonts, favicons, .riv, etc.)
  ├─ src/
  │  ├─ content/
  │  │  └─ config.ts        # schémas typés Astro Content Collections
  │  ├─ components/
  │  │  ├─ Hero.astro
  │  │  └─ SplineBlock.astro
  │  └─ pages/
  │     └─ index.astro
  └─ astro.config.mjs
```

---

## Typage strict et contenu typé (Astro Content)

**`src/content/config.ts`** (TypeScript strict, code en anglais, docs en français) :

```ts
// --------------------------------------------------------------------------------------
// Schéma de contenu typé pour pages/sections.
// - Objectif : valider les champs à la build, auto-completions dans les templates.
// --------------------------------------------------------------------------------------
import { z, defineCollection } from "astro:content";

/**
 * Collection "pages"
 * @description Décrit le format d'une page statique éditable.
 */
const pages = defineCollection({
  type: "content",
  schema: z.object({
    title: z.string().min(1),              // Titre de la page
    description: z.string().min(1),        // Meta description
    heroTagline: z.string().min(1),        // Slogan pour le hero
    published: z.boolean().default(true),  // Publication
    order: z.number().default(0),          // Tri nav
  }),
});

export const collections = { pages };
```

---

## Page d’accueil expressive (Astro + Tailwind + Motion)

**`src/pages/index.astro`**

```astro
---
import Hero from "../components/Hero.astro";
---

<html lang="fr">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Disruptive Static Site</title>
  </head>

  <body class="min-h-screen bg-neutral-950 text-neutral-100">
    <Hero />

    <!-- Motion: micro-interaction du CTA -->
    <script type="module">
      // -----------------------------------------------------------------------------
      // Animation d'impulsion sur le CTA (respecte le rendu statique d'Astro : script minimal côté client)
      // -----------------------------------------------------------------------------
      import { animate } from "motion";
      const prefersReduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
      if (!prefersReduced) {
        animate(".cta-pulse", { scale: [1, 1.04, 1] }, { duration: 1.1, repeat: Infinity });
      }
    </script>
  </body>
</html>
```

**`src/components/Hero.astro`**

```astro
---
/**
 * Composant Hero d'accueil.
 * @description Section hero avec accroche forte et call-to-action.
 */
---

<section class="relative isolate overflow-hidden px-6 py-24 md:px-8">
  <div class="mx-auto max-w-3xl">
    <h1 class="text-balance text-5xl font-extrabold tracking-tight md:text-7xl">
      Be bold. Ship static. Look stunning.
    </h1>
    <p class="mt-6 text-lg text-neutral-300">
      Zero fuss build. Island-level interactivity. CDN-grade speed.
    </p>
    <div class="mt-10 flex items-center gap-4">
      <a href="#start" class="cta-pulse inline-flex items-center rounded-md px-6 py-3 text-base font-semibold ring-1 ring-white/20 hover:bg-white/10">
        Launch now
      </a>
      <a href="#demo" class="text-sm opacity-80 hover:opacity-100 underline">See demo</a>
    </div>
  </div>
</section>
```

> Motion est documenté ici. ([Motion][3])

---

## “Wow factor” en 30 secondes

### Spline (3D légère à intégrer)

```html
<!-- Place ce script dans <head> ou avant </body> -->
<script type="module" src="https://unpkg.com/@splinetool/viewer@latest/build/spline-viewer.js"></script>

<!-- Dans ta page -->
<spline-viewer
  url="https://prod.spline.design/ton-projet/scene.splinecode"
  loading="lazy"
  aria-label="3D hero scene"
  style="width:100%;height:500px;border-radius:1rem;overflow:hidden"
></spline-viewer>
```

> Le web‑component `<spline-viewer>` est la manière recommandée pour embarquer une scène Spline. ([Spline Docs][5])

### Rive (micro‑interactions vectorielles)

```html
<!-- Variante simple via CDN -->
<script src="https://unpkg.com/@rive-app/webgl@latest"></script>

<canvas id="rive-logo" width="320" height="96" aria-label="Animated logo"></canvas>

<script>
  // -----------------------------------------------------------------------------
  // Joue un logo .riv (state machine) dans un canvas WebGL (performant et léger).
  // -----------------------------------------------------------------------------
  new rive.Rive({
    src: "/animations/logo.riv",
    canvas: document.getElementById("rive-logo"),
    autoplay: true
    // Exemple: stateMachines: ["Hover"], onLoad: (e) => { ... }
  });
</script>
```

> Runtimes Rive pour le web (JS/WASM), avec API haut niveau et WebGL/canvas. ([Rive][6], [GitHub][11])

---

## CMS (si tu veux éditer sans coder)

* **Decap CMS** (Git‑based). Avec Astro : ajoute `/admin` pour l’interface d’édition. ([Decap CMS][7], [Astro Docs][8])

---

## Déploiement & CI/CD

* **Cloudflare Pages** – connecte le repo, build `npm run build`, output `dist/`, previews auto par PR/commit. ([Cloudflare Docs][9])
* Ça reste 100% **statique** (HTML/CSS/JS), donc coûts très faibles et perf top. ([Cloudflare Docs][12])

---

## Check‑list qualité (rapide mais soignée)

* **Perf** : images locales optimisées (Astro `<Image />`), fonts variables locales, `rel=preload` sur la/les police(s).
* **A11y** : contrastes, `aria-label` sur 3D/anim, alternative statique si `prefers-reduced-motion`.
* **SEO** : title/description par page, OpenGraph de base.
* **Sécurité** : CSP simple (interdire tout sauf domaines nécessaires : self, unpkg pour Spline/Rive si tu ne self‑hostes pas), pas de secrets côté client, dépendances tenues à jour.
* **Tooling** : TypeScript strict, ESLint + Prettier, commits atomiques.

---

## Plan d’exécution (une journée, focus)

1. **Matin** – Scaffold Astro, Tailwind, structure pages, Hero + CTA + typographies.
2. **Début d’aprem** – Intègre Motion sur 2–3 interactions (CTA, reveal, hover cards). ([Motion][3])
3. **Fin d’aprem** – Ajoute Spline *ou* Rive sur le hero; peaufine a11y & perf. ([Spline Docs][5], [Rive][6])
4. **Déploiement** – Push → Cloudflare Pages (previews/PR); réglages DNS. ([Cloudflare Docs][9])

---

## Alternative minimaliste (si tu veux *encore* plus simple)

* **Eleventy (11ty)** + Tailwind, super straight‑forward, builds très rapides. ([Eleventy][13])

---

### Envie que je te génère un starter Astro déjà câblé avec Tailwind, Motion, un bloc Spline/Rive, une CSP de base et un workflow Cloudflare Pages ?

Je peux te livrer un squelette prêt à pousser en prod (avec TS strict, lint, et quelques composants).

[1]: https://docs.astro.build/en/concepts/islands/?utm_source=chatgpt.com "Islands architecture - Docs"
[2]: https://tailwindcss.com/?utm_source=chatgpt.com "Tailwind CSS - Rapidly build modern websites without ever leaving your ..."
[3]: https://motion.dev/?utm_source=chatgpt.com "Motion — React & JavaScript animation library"
[4]: https://www.npmjs.com/package/motion/v/10.17.0?utm_source=chatgpt.com "Motion One - npm"
[5]: https://docs.spline.design/doc/exporting-as-spline-viewer/docoQp6On9ht?utm_source=chatgpt.com "Exporting as Spline Viewer"
[6]: https://rive.app/docs/runtimes/web/web-js?utm_source=chatgpt.com "Web (JS) - Rive"
[7]: https://decapcms.org/docs/intro/?utm_source=chatgpt.com "Overview | Decap CMS | Open-Source Content Management System"
[8]: https://docs.astro.build/en/guides/cms/decap-cms/?utm_source=chatgpt.com "Decap CMS & Astro - Docs"
[9]: https://developers.cloudflare.com/pages/?utm_source=chatgpt.com "Overview · Cloudflare Pages docs"
[10]: https://developers.cloudflare.com/pages/get-started/?utm_source=chatgpt.com "Getting started · Cloudflare Pages docs"
[11]: https://github.com/rive-app/rive-wasm?utm_source=chatgpt.com "GitHub - rive-app/rive-wasm: Wasm/JS runtime for Rive"
[12]: https://developers.cloudflare.com/pages/framework-guides/deploy-anything/?utm_source=chatgpt.com "Static HTML · Cloudflare Pages docs"
[13]: https://www.11ty.dev/docs/?utm_source=chatgpt.com "Getting Started — Eleventy"
