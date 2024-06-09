import { file, spawn } from "bun";
import { consola } from "consola";

const proc = spawn([
	"bunx",
	"attw",
	"-f",
	"table-flipped",
	"--no-emoji",
	"--no-color",
	"--pack",
]);

const text = await new Response(proc.stdout).text();

const pkg = await file("package.json").json();

const entrypointLines = text
	.slice(text.indexOf(`"${pkg.name}/`))
	.split("\n")
	.filter(Boolean)
	.filter((line) => !line.includes("─"))
	.map((line) =>
		line
			.replaceAll(/[^\d "()/A-Za-z│-]/g, "")
			.replaceAll("90m│39m", "│")
			.replaceAll(/^│/g, "")
			.replaceAll(/│$/g, ""),
	);

const entrypoints = entrypointLines.map((entrypointLine) => {
	const [entrypoint, ...resolutionColumns] = entrypointLine.split("│");
	return {
		entrypoint: entrypoint.replace(pkg.name, ".").trim(),
		esm: resolutionColumns[2].trim(),
		bundler: resolutionColumns[3].trim(),
	};
});

const entrypointsWithProblems = entrypoints.filter(
	(item) => item.esm.includes("fail") || item.bundler.includes("fail"),
);

if (entrypointsWithProblems.length > 0) {
	consola.error("Entrypoints with problems:");
	process.exit(1);
} else {
	consola.success("All entrypoints are valid!");
}
