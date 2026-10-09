/** Child-process runner with timeout. */
import { spawn } from "node:child_process";

export function run(cmd: string, args: string[], timeoutMs = 15_000): Promise<string> {
  return new Promise((resolve, reject) => {
    const p = spawn(cmd, args, { stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    let done = false;
    const t = setTimeout(() => {
      if (!done) {
        done = true;
        p.kill();
        reject(new Error(`${cmd} timed out after ${timeoutMs}ms`));
      }
    }, timeoutMs);
    p.stdout.on("data", (d) => (out += d.toString()));
    p.stderr.on("data", (d) => (out += d.toString()));
    p.on("error", (e) => {
      if (!done) {
        done = true;
        clearTimeout(t);
        reject(e);
      }
    });
    p.on("close", (code) => {
      if (!done) {
        done = true;
        clearTimeout(t);
        if (code === 0) resolve(out);
        else reject(new Error(`${cmd} exited ${code}: ${out.slice(0, 500)}`));
      }
    });
  });
}
