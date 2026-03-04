/**
 * Post-build script: flattens Next.js 16 RSC payload directories into flat files.
 *
 * Next.js 16 static export generates RSC payloads in nested directories:
 *   dashboard/__next.dashboard/__PAGE__.txt
 *
 * But the client-side router requests them as flat files:
 *   dashboard/__next.dashboard.__PAGE__.txt
 *
 * This script copies the nested files to flat paths so static hosting can serve them.
 */
import { readdirSync, statSync, copyFileSync, existsSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const outDir = join(__dirname, "..", "out");

let count = 0;

function flattenDir(rscDir, parentDir, prefix) {
  for (const entry of readdirSync(rscDir, { withFileTypes: true })) {
    const fullPath = join(rscDir, entry.name);
    if (entry.isFile()) {
      const flatName = `${prefix}.${entry.name}`;
      const dest = join(parentDir, flatName);
      copyFileSync(fullPath, dest);
      count++;
    } else if (entry.isDirectory()) {
      flattenDir(fullPath, parentDir, `${prefix}.${entry.name}`);
    }
  }
}

function walk(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const fullPath = join(dir, entry.name);
    if (!entry.isDirectory()) continue;

    if (entry.name.startsWith("__next.")) {
      flattenDir(fullPath, dir, entry.name);
    } else if (!entry.name.startsWith("_next")) {
      walk(fullPath);
    }
  }
}

if (!existsSync(outDir)) {
  console.error("out/ directory not found – run next build first");
  process.exit(1);
}

walk(outDir);
console.log(`flatten-rsc: copied ${count} RSC payload files`);
