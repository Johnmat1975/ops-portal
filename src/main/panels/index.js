// Panel registry. Each panel exports { id, collect(api, env) -> raw, compute(raw) -> page model }.
// Raw pulls are cached per environment; compute runs on every load, so rule changes apply without re-pulling.
module.exports = Object.fromEntries([
  require('./licences'),
  require('./inspectors'),
  require('./email'),
  require('./coverage'),
  require('./identity'),
  require('./changes'),
  require('./lifecycle'),
  require('./network'),
  require('./ai'),
  require('./wallboard'),
  require('./compliance'),
  require('./cyber'),
  require('./lookup'),
  require('./register'),
  require('./actions'),
  require('./overview'),
  { id: 'stack', collect: require('../stack').collectEnv, compute: require('../stack').stackPage },
].map(p => [p.id, p]));
