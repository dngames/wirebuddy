/** Version from package.json, put in by the build (build.mjs). */
declare const __VERSION__: string;

export const VERSION: string = typeof __VERSION__ === "string" ? __VERSION__ : "dev";
