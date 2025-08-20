#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# Define paths
PROJECT_ROOT="/home/seb/Dev/miaou"
DOCS_DIR="$PROJECT_ROOT/docs"
WEB_DIR="$PROJECT_ROOT/web" # This will no longer be used for output by this script

# Create project-specific tmp directory if it doesn't exist
mkdir -p "$PROJECT_ROOT/tmp"
TEMP_ASTRO_DIR=$(mktemp -d "$PROJECT_ROOT/tmp/astro-XXXXXXXXXX")

echo "--- Starting Astro website generation ---"

# 1. Check for Node.js and npm
if ! command -v node &> /dev/null
then
    echo "Node.js is not installed. Please install it to proceed."
    exit 1
fi

if ! command -v npm &> /dev/null
then
    echo "npm is not installed. Please install it to proceed."
    exit 1
fi

echo "Node.js and npm found. Proceeding..."

# 2. Clean previous build (no longer cleaning WEB_DIR as it's not the output)
# rm -rf "$WEB_DIR"
# mkdir -p "$WEB_DIR"

# 3. Scaffold a new Astro project in a temporary directory
echo "Scaffolding new Astro project in temporary directory: $TEMP_ASTRO_DIR"
# Use --yes to skip prompts for npm create astro
npm create astro@latest "$TEMP_ASTRO_DIR" -- --template basics --yes

# Change to the temporary Astro project directory
cd "$TEMP_ASTRO_DIR"

# 4. Install npm dependencies
echo "Installing npm dependencies..."
npm install

# 5. Add Tailwind CSS (but not the Astro integration)
echo "Installing Tailwind CSS..."
npm install tailwindcss

# 6. Install Autoprefixer and @tailwindcss/postcss
echo "Installing Autoprefixer and @tailwindcss/postcss..."
npm install autoprefixer @tailwindcss/postcss

# 7. Add Motion
echo "Adding Motion library..."
npm i motion

# 8. Copy docs content to Astro's content directory
echo "Copying Markdown files from $DOCS_DIR to $TEMP_ASTRO_DIR/src/content/pages/"
mkdir -p "$TEMP_ASTRO_DIR/src/content/pages/"
cp -r "$DOCS_DIR/." "$TEMP_ASTRO_DIR/src/content/pages/"

# 9. Create src/content/config.ts (with optional fields)
echo "Creating src/content/config.ts..."
cat << 'EOF' > "$TEMP_ASTRO_DIR/src/content/config.ts"
import { z, defineCollection } from "astro:content";

const pages = defineCollection({
  type: "content",
  schema: z.object({
    title: z.string().min(1).optional(), // Made optional
    description: z.string().min(1).optional(), // Made optional
    heroTagline: z.string().min(1).optional(), // Made optional
    published: z.boolean().default(true),
    order: z.number().default(0),
  }),
});

export const collections = { pages };
EOF

# 10. Create src/components/Hero.astro
echo "Creating src/components/Hero.astro..."
cat << 'EOF' > "$TEMP_ASTRO_DIR/src/components/Hero.astro"
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
EOF

# 11. Create src/components/MotionInitializer.astro
echo "Creating src/components/MotionInitializer.astro..."
mkdir -p "$TEMP_ASTRO_DIR/src/components/"
cat << 'EOF' > "$TEMP_ASTRO_DIR/src/components/MotionInitializer.astro"
---
// No JavaScript here, only Astro component logic if needed
---

<script>
  // This script tag is client-side, Astro will bundle it.
  // The import is handled by Astro/Vite during build.
  import { animate } from "motion";

  const prefersReduced =
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  if (!prefersReduced) {
    window.addEventListener('DOMContentLoaded', () => {
      animate(".cta-pulse", { scale: [1, 1.04, 1] }, { duration: 1.1, repeat: Infinity });
    });
  }
</script>
EOF

# 12. Create src/styles/global.css
echo "Creating src/styles/global.css..."
mkdir -p "$TEMP_ASTRO_DIR/src/styles/"
cat << 'EOF' > "$TEMP_ASTRO_DIR/src/styles/global.css"
/* This file is used by Astro's Tailwind integration to inject CSS */
@tailwind base;
@tailwind components;
@tailwind utilities;
EOF

# 13. Create src/layouts/BaseLayout.astro
echo "Creating src/layouts/BaseLayout.astro..."
mkdir -p "$TEMP_ASTRO_DIR/src/layouts/"
cat << 'EOF' > "$TEMP_ASTRO_DIR/src/layouts/BaseLayout.astro"
---
import '../styles/global.css';

interface Props {
  title: string;
}

const { title } = Astro.props;
---

<html lang="fr">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>{title}</title>

    <!-- CSP stricte : aucun domaine externe -->
    <meta http-equiv="Content-Security-Policy"
      content="default-src 'self'; img-src 'self' data: blob:; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self' data:; connect-src 'self'; object-src 'none'">
    <!-- Base relative pour un usage via file:// -->
    <base href="./">
  </head>

  <body class="min-h-screen bg-neutral-950 text-neutral-100">
    <slot />
  </body>
</html>
EOF

# 14. Modify src/pages/index.astro (using BaseLayout and listing content)
echo "Modifying src/pages/index.astro..."
cat << 'EOF' > "$TEMP_ASTRO_DIR/src/pages/index.astro"
---
import Hero from "../components/Hero.astro";
import MotionInitializer from "../components/MotionInitializer.astro";
import BaseLayout from "../layouts/BaseLayout.astro";
import { getCollection } from 'astro:content';

const allPages = await getCollection('pages');
---

<BaseLayout title="Miaou Documentation">
  <Hero />

  <main class="mx-auto max-w-3xl px-6 py-12">
    <h2 class="text-3xl font-bold text-white mb-6">Documentation Pages</h2>
    <ul class="list-disc list-inside text-neutral-300">
      {
        allPages.map((page) => (
          <li>
            <a href={`/${page.slug}/`} class="text-blue-400 hover:underline">
              {page.data.title || page.slug.replace(/-/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
            </a>
          </li>
        ))
      }
    </ul>
  </main>

  <!-- Motion packagé localement via npm (aucun CDN) -->
  <MotionInitializer />
</BaseLayout>
EOF

# 15. Create src/pages/[...slug].astro (using BaseLayout for content pages)
echo "Creating src/pages/[...slug].astro..."
cat << 'EOF' > "$TEMP_ASTRO_DIR/src/pages/[...slug].astro"
---
import { getCollection } from 'astro:content';
import BaseLayout from "../layouts/BaseLayout.astro";

export async function getStaticPaths() {
  const allPages = await getCollection('pages');
  return allPages.map((page) => ({
    params: { slug: page.slug },
    props: { page },
  }));
}

const { page } = Astro.props;
const { Content } = await page.render();
---

<BaseLayout title={page.data.title || page.slug.replace(/-/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}>
  <main class="mx-auto max-w-3xl px-6 py-12">
    <a href="/" class="text-blue-400 hover:underline mb-6 block">&larr; Back to Home</a>
    <h1 class="text-4xl font-extrabold text-white mb-4">{page.data.title || page.slug.replace(/-/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}</h1>
    <div class="prose prose-invert prose-lg max-w-none">
      <Content />
    </div>
  </main>
</BaseLayout>
EOF

# 16. Configure astro.config.mjs
echo "Configuring astro.config.mjs..."
cat << 'EOF' > "$TEMP_ASTRO_DIR/astro.config.mjs"
import { defineConfig } from "astro/config";
// Removed: import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  output: "static",
  trailingSlash: "always",
  build: {
    assets: "_astro",
    assetsPrefix: undefined,
  },
  // Removed: integrations: [tailwindcss()],
});
EOF

# 17. Create postcss.config.cjs
echo "Creating postcss.config.cjs..."
cat << 'EOF' > "$TEMP_ASTRO_DIR/postcss.config.cjs"
module.exports = {
  plugins: {
    '@tailwindcss/postcss': {},
    autoprefixer: {},
  },
};
EOF

# 18. Build the Astro project
echo "Building the Astro project..."
npm run build

# 19. Start the preview server directly from the temporary directory
echo "--- Astro website generation complete! ---"
echo "Starting preview server from $TEMP_ASTRO_DIR. Press Ctrl+C to stop."
npm run preview

# The script will block here until the server is stopped.
# The temporary directory will NOT be cleaned up automatically by this script.
