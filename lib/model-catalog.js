/**
 * Q Mobile read-only model discovery, isolated from QQ transport.
 * Failure and slow providers must never block official QQ startup or replies.
 */
export const MODELS_PATH = '/qqbot/q-mobile/models';
const valid = (value, max) => typeof value === 'string' && value.length > 0 &&
  value.length <= max && !/[\u0000-\u001f<>]/u.test(value);

// Bound each slow host integration: up to 20 providers in four workers.
// Timeouts only affect this optional settings picker, never QQ inference.
async function withDeadline(ms, work, fallback) {
  let timer;
  try {
    return await Promise.race([
      Promise.resolve().then(work),
      new Promise(resolve => { timer = setTimeout(() => resolve(fallback), ms); })
    ]);
  } catch {
    return fallback;
  } finally {
    clearTimeout(timer);
  }
}
export async function discoverModels(llm) {
  if (typeof llm?.listProviders !== 'function' ||
      typeof llm?.listModels !== 'function') return [];
  const providers = await withDeadline(1200, () => llm.listProviders(), []);
  if (!Array.isArray(providers)) return [];
  const candidates = providers.slice(0, 20).map(entry =>
    typeof entry === 'string' ? entry : entry?.id);
  const grouped = Array.from({ length: candidates.length }, () => []);
  let next = 0;
  const worker = async () => {
    while (next < candidates.length) {
      const index = next++;
      const provider = candidates[index];
      if (!valid(provider, 96)) continue;
      const models = await withDeadline(900, () => llm.listModels(provider), []);
      if (!Array.isArray(models)) continue;
      grouped[index] = models.slice(0, 35).map(entry => {
        const id = typeof entry === 'string' ? entry : entry?.id;
        const name = typeof entry === 'string' ? entry : entry?.name;
        if (!valid(id, 200)) return null;
        return { provider, id, name: valid(name, 160) ? name : id };
      }).filter(Boolean);
    }
  };
  await Promise.all(Array.from({ length: Math.min(4, candidates.length) }, worker));
  const items = [];
  const seen = new Set();
  for (const group of grouped) {
    for (const item of group) {
      const key = item.provider + '\u0001' + item.id;
      if (seen.has(key)) continue;
      seen.add(key);
      items.push(item);
      if (items.length >= 120) return items;
    }
  }
  return items;
}
function respond(res, status, value) {
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff'
  });
  res.end(JSON.stringify(value));
}
function sameOrigin(req) {
  if (!req?.headers?.origin) return true; // DSH internal authenticated bridge
  try { return new URL(req.headers.origin).host === req.headers.host; }
  catch { return false; }
}
export async function catalogHandler(req, res, llm, loadModels = () => discoverModels(llm)) {
  if (req.method !== 'GET') return respond(res, 405, { error: 'method_not_allowed' });
  if (!sameOrigin(req)) return respond(res, 403, { error: 'origin_rejected' });
  try {
    const models = await loadModels();
    return respond(res, 200, { models, available: models.length > 0 });
  } catch {
    return respond(res, 200, { models: [], available: false });
  }
}
export function installModelCatalog(ctx) {
  if (typeof ctx?.inject !== 'function') return false;
  try {
    ctx.inject(['webServer', 'llm'], scope => {
      if (typeof scope.effect !== 'function' ||
          typeof scope.webServer?.register !== 'function' || !scope.llm) return;
      let models = [];
      let expiresAt = 0;
      let pending = null;
      const loadModels = () => {
        if (Date.now() < expiresAt) return Promise.resolve(models);
        if (pending) return pending;
        pending = discoverModels(scope.llm).then(result => {
          models = result;
          expiresAt = Date.now() + (result.length ? 20000 : 3000);
          return models;
        }).finally(() => { pending = null; });
        return pending;
      };
      scope.effect(() => scope.webServer.register({
        kind: 'exact', path: MODELS_PATH,
        handler: (req, res) => catalogHandler(req, res, scope.llm, loadModels)
      }));
    });
    return true;
  } catch { return false; }
}
