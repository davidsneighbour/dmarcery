import { createLintStagedConfig } from "@dnbhq/lintstaged-config";
import type { Configuration } from "lint-staged";

const config: Configuration = createLintStagedConfig({
  // There is no local .secretlintrc; the wrapper injects @dnbhq/secretlint-config.
  secrets: { commands: ["dnb-secretlint --no-glob"] },
  markdown: {
    // The default glob "!(CHANGELOG)**/*.{md,markdown,mdx}" never matches files in the
    // repository root (README.md) and does not exclude nested CHANGELOG.md files.
    // Remove when https://github.com/davidsneighbour/lintstaged-config/issues/2 is released.
    glob: "**/!(CHANGELOG).{md,markdown,mdx}",
    // There is no local .markdownlint-cli2.jsonc; use the shared config directly.
    configPath:
      "./node_modules/@dnbhq/markdownlint-config/.markdownlint-cli2.jsonc",
  },
});

export default config;
