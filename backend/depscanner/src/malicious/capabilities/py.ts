/**
 * Python capability detector.
 *
 * Pattern set targets the standard Python APIs malicious packages use to
 * exfiltrate, persist, or execute remote code (subprocess, urllib, eval,
 * pickle.loads, ctypes). install_script is detected from setup.py /
 * pyproject.toml in `manifest.ts`, not here.
 */
import type { CapabilityDetector, CapabilitySet } from './types';

const EXTS = ['.py', '.pyi'];

const RX_SPAWNS = /\b(?:subprocess\.(?:run|Popen|call|check_call|check_output)|os\.(?:system|popen|spawn[lvep]+|exec[lvep]+))\b/;
const RX_NETWORK = /\b(?:urllib\.request|urllib2|http\.client|httplib|requests\.(?:get|post|put|delete|patch|request|Session)|httpx\.(?:get|post|Client|AsyncClient)|aiohttp\.ClientSession|socket\.socket|telnetlib|ftplib)\b|\bimport\s+(?:requests|httpx|aiohttp|urllib3)\b|\bfrom\s+(?:requests|httpx|aiohttp|urllib3)\s+import\b/;
const RX_EVAL = /(?<![\w.])eval\s*\(|(?<![\w.])exec\s*\(|\bcompile\s*\(/;
const RX_NATIVE = /\bctypes\.(?:CDLL|cdll|windll|oledll|PyDLL)\b|\bcffi\.FFI\b|\bimport\s+ctypes\b|\bfrom\s+ctypes\s+import\b/;
// Bounded `[^,)\n]{0,200}` instead of unbounded `[^)]*` — a malicious
// `.py` containing many `open(` token starts followed by commas without a
// matching mode quote ('open(a,'.repeat(N) + 'X') would otherwise drive
// quadratic backtracking on the original engine. Measured pre-fix: 205KB→3s,
// 342KB→8s; at the 5MB MAX_FILE_BYTES cap the worker event loop blocks for
// minutes. The 200-char ceiling covers any realistic `open(path, mode)`
// call site without giving the engine room to retry across thousands of
// comma positions.
const RX_FS_WRITE = /\bopen\s*\([^,)\n]{0,200},\s*['"](?:w|a|x|wb|ab|xb|w\+|a\+|x\+|rb\+|wb\+|ab\+|xb\+)['"]|\bos\.(?:write|remove|unlink|rmdir|removedirs|rename|replace|mkdir|makedirs)\b|\bshutil\.(?:copy|copy2|copyfile|copytree|move|rmtree)\b|\bpathlib\.[\w.]+\.(?:write_text|write_bytes|unlink|rename|mkdir|rmdir)\b/;
const RX_CRYPTO = /\bimport\s+(?:hashlib|hmac|secrets)\b|\bfrom\s+(?:hashlib|hmac|secrets|cryptography|Crypto|nacl)\b|\bhashlib\.(?:md5|sha1|sha256|sha512|new)\b|\bcryptography\.(?:fernet|hazmat)\b/;
const RX_SERDE = /\bpickle\.(?:loads?|Unpickler)\b|\bcPickle\.loads?\b|\bmarshal\.loads?\b|\bdill\.loads?\b|\byaml\.(?:load|unsafe_load|full_load)\s*\(|\bxml\.etree\.ElementTree\.parse\b/;
const RX_DNS = /\bsocket\.(?:gethostbyname|gethostbyname_ex|getaddrinfo|gethostbyaddr)\b|\bimport\s+dns\.resolver\b|\bdns\.resolver\.Resolver\b/;
const RX_WS = /\bimport\s+(?:websockets|websocket)\b|\bfrom\s+websockets\b|\bwebsocket\.WebSocketApp\b|\baiohttp\.ws_connect\b/;
const RX_SIGNAL = /\bsignal\.(?:signal|SIG[A-Z]+)\b|\bos\.kill\s*\(/;
const RX_BASE64 = /\bbase64\.(?:b64decode|standard_b64decode|urlsafe_b64decode)\s*\(\s*(b?['"])[A-Za-z0-9+/=]{200,}\1/;
const RX_DYNIMPORT = /\bimportlib\.import_module\s*\(\s*(?!['"`])[^)]+\)|\b__import__\s*\(\s*(?!['"`])[^)]+\)/;
const RX_ENV = /\bos\.(?:environ|getenv|putenv)\b|\bimport\s+os\b\s*[\s\S]*?os\.environ/;
const RX_CLIPBOARD = /\bimport\s+(?:pyperclip|clipboard|pyperclip3)\b|\bfrom\s+(?:pyperclip|clipboard)\b/;

export const pyDetector: CapabilityDetector = {
  language: 'python',
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
      dynamic_import: RX_DYNIMPORT.test(source),
      reads_env: RX_ENV.test(source),
      clipboard_access: RX_CLIPBOARD.test(source),
    };
  },
};
