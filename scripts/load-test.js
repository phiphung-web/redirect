const http = require("http");
const https = require("https");

const target = process.env.LOAD_TARGET;
const concurrency = Number.parseInt(process.env.LOAD_CONCURRENCY || "20", 10);
const durationSeconds = Number.parseInt(process.env.LOAD_DURATION_SECONDS || "30", 10);

if (!target) {
  console.error("Set LOAD_TARGET to a test campaign URL. Production targets are not recommended.");
  process.exit(1);
}

const url = new URL(target);
const transport = url.protocol === "https:" ? https : http;
const endAt = Date.now() + durationSeconds * 1000;
const timings = [];
let completed = 0;
let failed = 0;

const requestOnce = () =>
  new Promise((resolve) => {
    const startedAt = process.hrtime.bigint();
    const req = transport.get(url, { timeout: 5000 }, (res) => {
      res.resume();
      res.on("end", () => {
        const elapsed = Number(process.hrtime.bigint() - startedAt) / 1e6;
        timings.push(elapsed);
        completed += 1;
        if (res.statusCode >= 500) failed += 1;
        resolve();
      });
    });
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", () => {
      failed += 1;
      resolve();
    });
  });

const worker = async () => {
  while (Date.now() < endAt) await requestOnce();
};

Promise.all(Array.from({ length: concurrency }, worker)).then(() => {
  timings.sort((a, b) => a - b);
  const percentile = (value) =>
    timings[Math.min(timings.length - 1, Math.floor(timings.length * value))] || 0;
  console.log(
    JSON.stringify(
      {
        target: url.origin + url.pathname,
        durationSeconds,
        concurrency,
        completed,
        failed,
        requestsPerSecond: Number((completed / durationSeconds).toFixed(2)),
        p50Ms: Number(percentile(0.5).toFixed(2)),
        p95Ms: Number(percentile(0.95).toFixed(2)),
        p99Ms: Number(percentile(0.99).toFixed(2)),
      },
      null,
      2
    )
  );
});
