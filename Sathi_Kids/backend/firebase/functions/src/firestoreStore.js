'use strict';
/** Firestore implementation of the store interface used by domain.js. Paths like "families/x/members" are collections. */
class FirestoreStore {
  constructor(db) {
    this.db = db;
  }

  ref(c, id) {
    return this.db.collection(c).doc(id);
  }

  static snapToDoc(s) {
    return s.exists ? s.data() : null;
  }

  queryRef(c, filters) {
    let q = this.db.collection(c);
    for (const [f, v] of filters) q = q.where(f, '==', v);
    return q;
  }

  async get(c, id) {
    if (typeof id !== 'string' || !id) return null;
    return FirestoreStore.snapToDoc(await this.ref(c, id).get());
  }

  async query(c, filters) {
    const snap = await this.queryRef(c, filters).get();
    return snap.docs.map((d) => ({ id: d.id, ...d.data() }));
  }

  async transaction(fn) {
    return this.db.runTransaction(async (t) => {
      const tx = {
        get: async (c, id) => (typeof id === 'string' && id ? FirestoreStore.snapToDoc(await t.get(this.ref(c, id))) : null),
        query: async (c, f) => (await t.get(this.queryRef(c, f))).docs.map((d) => ({ id: d.id, ...d.data() })),
        set: async (c, id, d) => { t.set(this.ref(c, id), d); },
        update: async (c, id, p) => { t.update(this.ref(c, id), p); },
      };
      return fn(tx);
    });
  }
}

module.exports = { FirestoreStore };
