'use strict';
/**
 * Google Cloud Web Risk Lookup API client (uris.search), server-side only.
 * Docs: https://cloud.google.com/web-risk/docs/lookup-api
 *   GET https://webrisk.googleapis.com/v1/uris:search?threatTypes=...&uri=...&key=API_KEY
 *   match: {"threat":{"threatTypes":["MALWARE"],"expireTime":"..."}}   no match: {}
 * The API key comes from Secret Manager (WEBRISK_API_KEY). URLs are never logged.
 */
const THREAT_TYPES = ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'];

function makeWebRisk(apiKey, fetchImpl = fetch, timeoutMs = 3500) {
  if (!apiKey) return null;
  return {
    async search(url) {
      const qs = THREAT_TYPES.map((t) => `threatTypes=${t}`).join('&') + `&uri=${encodeURIComponent(url)}&key=${encodeURIComponent(apiKey)}`;
      const ctl = new AbortController();
      const timer = setTimeout(() => ctl.abort(), timeoutMs);
      try {
        const res = await fetchImpl(`https://webrisk.googleapis.com/v1/uris:search?${qs}`, { signal: ctl.signal });
        if (res.status !== 200) throw new Error(`webrisk_http_${res.status}`);
        const body = await res.json();
        if (!body || typeof body !== 'object') throw new Error('webrisk_bad_body');
        if (!body.threat) return [];
        const types = Array.isArray(body.threat.threatTypes) ? body.threat.threatTypes.filter((t) => typeof t === 'string') : [];
        if (types.length === 0) throw new Error('webrisk_bad_body');
        return types;
      } finally {
        clearTimeout(timer);
      }
    },
  };
}

module.exports = { makeWebRisk, THREAT_TYPES };
