/**
 * JavaScript / TypeScript capability detector.
 *
 * Regex-based identifier matching against unpacked package source. False
 * positives from string literals or comments are acceptable for malicious-
 * package signal: a comment explaining "we use child_process.spawn here"
 * still warrants a flag in the drawer. Minified packages are caught by
 * GuardDog separately and surface as a different finding class.
 */
import type { CapabilityDetector, CapabilitySet } from './types';

const EXTS = ['.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.mts', '.cts'];

const RX_SPAWNS = /\b(child_process)\b|require\((['"])child_process\2\)|\b(execSync|execFileSync|spawnSync|spawn|exec|fork|execFile)\s*\(|\bBun\.spawn\s*\(/;
const RX_NETWORK = /\bfetch\s*\(|require\((['"])(?:http|https|node-fetch|axios|got|request|undici)\1\)|from\s+['"](?:axios|node-fetch|got|undici)['"]|\b(?:XMLHttpRequest|http\.request|https\.request|http\.get|https\.get)\b/;
const RX_EVAL = /\beval\s*\(|new\s+Function\s*\(|\bvm\.(?:runIn|compile)|require\((['"])vm\1\)/;
const RX_NATIVE = /require\((['"])[^'"]*\.node\1\)|\bprocess\.dlopen\s*\(|require\((['"])bindings\2\)|require\((['"])node-gyp-build\3\)/;
const RX_FS_WRITE = /\bfs\.(?:writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream|truncate|truncateSync|copyFile|copyFileSync|rename|renameSync|unlink|unlinkSync|rm|rmSync|rmdir|rmdirSync|mkdir|mkdirSync)\b|\bfs\/promises\b|\bfsPromises\.(?:writeFile|appendFile|copyFile|rename|unlink|rm|mkdir)\b/;
const RX_CRYPTO = /require\((['"])crypto\1\)|from\s+['"]crypto['"]|\bcrypto\.(?:createCipher|createDecipher|createHash|createHmac|createSign|createVerify|generateKey|randomBytes|subtle)\b|\bcrypto\.subtle\b|require\((['"])bcrypt\2\)/;
const RX_SERDE = /require\((['"])(?:node-serialize|js-yaml|xml2js|serialize-javascript)\1\)|\bunserialize\s*\(|\bjsYaml\.load\s*\(|\byaml\.load\s*\(|\bnodeSerialize\.unserialize\s*\(/;
const RX_DNS = /require\((['"])dns(?:\/promises)?\1\)|\bdns\.(?:lookup|resolve|resolve4|resolve6|resolveMx|resolveTxt|resolveCname|reverse)\b/;
const RX_WS = /\bnew\s+WebSocket\s*\(|require\((['"])ws\1\)|require\((['"])socket\.io-client\2\)|from\s+['"]ws['"]|from\s+['"]socket\.io-client['"]/;
const RX_SIGNAL = /\bprocess\.kill\s*\(|\bprocess\.on\s*\(\s*['"]SIG[A-Z]+['"]|require\((['"])signal-exit\1\)/;
const RX_BASE64 = /Buffer\.from\s*\(\s*(['"`])[A-Za-z0-9+/=]{200,}\1\s*,\s*(['"])base64\2\s*\)|atob\s*\(\s*(['"`])[A-Za-z0-9+/=]{200,}\3\s*\)/;
const RX_DYNIMPORT = /\bimport\s*\(\s*(?!['"])[^)]/m;
const RX_REQUIRE_VAR = /\brequire\s*\(\s*(?!['"`])[^)]+\)/;
const RX_ENV = /\bprocess\.env\b/;
const RX_CLIPBOARD = /require\((['"])(?:clipboardy|clipboard|copy-paste)\1\)|from\s+['"](?:clipboardy|clipboard|copy-paste)['"]|\bnavigator\.clipboard\b|\belectron\.clipboard\b/;

export const jsDetector: CapabilityDetector = {
  language: 'javascript',
  supportsFile(p) {
    return EXTS.some((e) => p.endsWith(e));
  },
  detect(source): Partial<CapabilitySet> {
    return {
      spawns_processes: RX_SPAWNS.test(source),
      network_io: RX_NETWORK.test(source),
      eval_dynamic: RX_EVAL.test(source),
      native_addon_load: RX_NATIVE.test(source),
      filesystem_write: RX_FS_WRITE.test(source),
      crypto_operations: RX_CRYPTO.test(source),
      serialization_deser: RX_SERDE.test(source),
      dns_query: RX_DNS.test(source),
      websocket: RX_WS.test(source),
      process_signal: RX_SIGNAL.test(source),
      encrypted_payload: RX_BASE64.test(source),
      dynamic_import: RX_DYNIMPORT.test(source) || RX_REQUIRE_VAR.test(source),
      reads_env: RX_ENV.test(source),
      clipboard_access: RX_CLIPBOARD.test(source),
      // install_script handled at manifest level by detector orchestrator
    };
  },
};
