# Performance profile

Measured on 2026-07-21 on the production Contabo VPS:

- 6 AMD EPYC vCPU;
- 12 GB RAM;
- 200 GB SSD;
- Ubuntu 24.04, Node.js 20, PostgreSQL 16;
- internal loopback requests to `/healthz`, which performs a PostgreSQL readiness query;
- 15-second samples with zero failed requests.

| Profile | Concurrency | Requests/second | p50 | p95 | p99 |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 redirect worker | 50 | 1,512.60 | 25.33 ms | 76.31 ms | 149.67 ms |
| 1 redirect worker | 150 | 1,788.00 | 75.02 ms | 148.44 ms | 254.23 ms |
| 4 redirect workers | 50 | 4,036.47 | 8.08 ms | 33.40 ms | 81.83 ms |
| 4 redirect workers | 150 | 5,145.33 | 21.44 ms | 76.98 ms | 149.52 ms |
| 4 redirect workers | 300 | 4,879.00 | 47.50 ms | 147.25 ms | 334.74 ms |

The selected operating profile uses four redirect workers, one admin worker, an eight-connection PostgreSQL pool per process, 2 GB PostgreSQL shared buffers, an 8 GB effective cache estimate and 4 GB emergency swap with swappiness 10.

The concurrency-150 result improved throughput by about 2.88x and reduced median latency by about 71%. At concurrency 300 throughput begins to flatten, so four workers preserve CPU headroom for PostgreSQL, Nginx and traffic spikes.

These figures are an internal capacity comparison, not a promise of public internet throughput. Real campaigns also perform routing, rendering, buffered logging, TLS and network transfer. Benchmark an actual staging domain before setting a customer-facing sustained-traffic limit.
