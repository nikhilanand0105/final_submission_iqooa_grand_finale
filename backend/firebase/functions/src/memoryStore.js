'use strict';
/** In-memory implementation of the store interface used by domain.js (tests only). Transactions are serialised. */
class MemoryStore {
  constructor() {
    this.data = new Map(); // collection -> Map(id -> doc)
    this.lock = Promise.resolve();
  }

  col(c) {
    if (!this.data.has(c)) this.data.set(c, new Map());
    return this.data.get(c);
  }

  async get(c, id) {
    if (typeof id !== 'string') return null;
    const d = this.col(c).get(id);
    return d ? JSON.parse(JSON.stringify(d)) : null;
  }

  async set(c, id, doc) {
    this.col(c).set(id, JSON.parse(JSON.stringify(doc)));
  }

  async update(c, id, patch) {
    const cur = this.col(c).get(id);
    if (!cur) throw new Error('update on missing doc');
    this.col(c).set(id, { ...cur, ...JSON.parse(JSON.stringify(patch)) });
  }

  async query(c, filters) {
    const out = [];
    for (const [id, d] of this.col(c)) {
      if (filters.every(([f, v]) => d[f] === v)) out.push({ id, ...JSON.parse(JSON.stringify(d)) });
    }
    return out;
  }

  /** Runs fn with buffered writes; commits only if fn succeeds (like a Firestore transaction). */
  async transaction(fn) {
    const run = async () => {
      const writes = [];
      const tx = {
        get: (c, id) => this.get(c, id),
        query: (c, f) => this.query(c, f),
        set: async (c, id, d) => { writes.push(() => this.set(c, id, d)); },
        update: async (c, id, p) => {
          if (!this.col(c).has(id)) throw new Error('update on missing doc');
          writes.push(() => this.update(c, id, p));
        },
      };
      const result = await fn(tx);
      for (const w of writes) await w();
      return result;
    };
    const p = this.lock.then(run, run);
    this.lock = p.catch(() => {});
    return p;
  }
}

module.exports = { MemoryStore };
