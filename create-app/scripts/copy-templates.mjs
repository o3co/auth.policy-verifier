import { cpSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const src = resolve(__dirname, "../../templates/standalone");
const dest = resolve(__dirname, "../templates/standalone");

const EXCLUDED_DIRS = new Set(["node_modules", "dist"]);

rmSync(dest, { recursive: true, force: true });
cpSync(src, dest, {
	recursive: true,
	filter: (source) => {
		const segments = source.split(sep);
		return !segments.some((segment) => EXCLUDED_DIRS.has(segment));
	},
});

// Embed package versions so they're available at runtime without
// traversing the monorepo source tree (which won't exist in published tarballs).
const readVersion = (pkgPath) => {
	const pkg = JSON.parse(readFileSync(resolve(__dirname, pkgPath), "utf-8"));
	return pkg.version ?? "0.0.0";
};

const versions = {
	"@o3co/auth.policy-verifier.core": readVersion("../../packages/core/package.json"),
	"@o3co/auth.policy-verifier.builtins": readVersion("../../packages/builtins/package.json"),
	"@o3co/auth.policy-verifier.server": readVersion("../../packages/server/package.json"),
};

writeFileSync(resolve(dest, "..", "versions.json"), `${JSON.stringify(versions, null, "\t")}\n`);

// Inline tsconfig.base.json into the template's tsconfig.json so scaffolded
// projects work standalone without the monorepo's base config.
const baseTsconfig = JSON.parse(
	readFileSync(resolve(__dirname, "../../tsconfig.base.json"), "utf-8"),
);
const templateTsconfigPath = resolve(dest, "tsconfig.json");
const templateTsconfig = JSON.parse(readFileSync(templateTsconfigPath, "utf-8"));
delete templateTsconfig.extends;
templateTsconfig.compilerOptions = {
	...baseTsconfig.compilerOptions,
	...templateTsconfig.compilerOptions,
};
writeFileSync(templateTsconfigPath, `${JSON.stringify(templateTsconfig, null, "\t")}\n`);

console.log("Templates copied to create-app/templates/standalone");
