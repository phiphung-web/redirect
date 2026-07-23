const { performance } = require("../config/app");

class TtlCache {
  constructor(name) {
    this.name = name;
    this.values = new Map();
    this.hits = 0;
    this.misses = 0;
  }

  get(key) {
    if (!performance.cacheEnabled) return undefined;
    const item = this.values.get(key);
    if (!item) {
      this.misses += 1;
      return undefined;
    }
    if (item.expiresAt <= Date.now()) {
      if (item.staleUntil <= Date.now()) this.values.delete(key);
      this.misses += 1;
      return undefined;
    }
    this.hits += 1;
    return item.value;
  }

  set(key, value, ttlMs = performance.cacheTtlMs) {
    if (!performance.cacheEnabled) return value;
    if (this.values.size >= performance.cacheMaxEntries) {
      const oldestKey = this.values.keys().next().value;
      if (oldestKey !== undefined) this.values.delete(oldestKey);
    }
    const now = Date.now();
    this.values.set(key, {
      value,
      expiresAt: now + ttlMs,
      staleUntil: now + ttlMs + performance.cacheStaleTtlMs,
    });
    return value;
  }

  getStale(key) {
    const item = this.values.get(key);
    if (!item || item.staleUntil <= Date.now()) return undefined;
    return item.value;
  }

  delete(key) {
    this.values.delete(key);
  }

  clear() {
    this.values.clear();
  }

  stats() {
    return {
      name: this.name,
      entries: this.values.size,
      hits: this.hits,
      misses: this.misses,
    };
  }
}

const domainCache = new TtlCache("domains");
const campaignCache = new TtlCache("campaigns");
const shortLinkCache = new TtlCache("short-links");

const clearRuntimeCache = () => {
  domainCache.clear();
  campaignCache.clear();
  shortLinkCache.clear();
};

module.exports = {
  TtlCache,
  domainCache,
  campaignCache,
  shortLinkCache,
  clearRuntimeCache,
  getRuntimeCacheStats: () => [
    domainCache.stats(),
    campaignCache.stats(),
    shortLinkCache.stats(),
  ],
};
