// Isolate test runs from any real local Snyk CLI config (~/.config/configstore/snyk.json).
// getConfig() in src/lib/request/requestManager.ts falls back to that file's `endpoint`
// value when SNYK_API isn't set, which can silently differ from DEFAULT_API (e.g. missing
// the /v1 suffix after `snyk auth`) and break nock mocks that expect the /v1-prefixed paths.
// Forcing it here runs before any test file loads.
process.env.SNYK_API = 'https://api.snyk.io/v1';