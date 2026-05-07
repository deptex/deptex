/**
 * Ruby capability detector. Patterns target the typical malicious-gem
 * payload surface: backticks, system, eval, Marshal.load, OpenURI, etc.
 * install_script via .gemspec extensions handled in `manifest.ts`.
 */
import type { CapabilityDetector, CapabilitySet } from './types';

const EXTS = ['.rb', '.rake', '.gemspec'];

const RX_SPAWNS = /(?:^|[^A-Za-z0-9_])(?:system|exec|spawn|`[^`]+`)\s*\(?|\bIO\.popen\s*\(|\bOpen3\.(?:popen3|capture[23]|capture3)\s*\(|\bKernel\.(?:system|exec|spawn)\s*\(/;
const RX_NETWORK = /\brequire\s+['"]net\/(?:http|https|ftp|smtp|pop|imap|telnet)['"]|\brequire\s+['"]open-uri['"]|\bNet::HTTP(?:S)?\b|\bURI\.open\s*\(|\bHTTParty\b|\bFaraday\b/;
const RX_EVAL = /(?:^|[^A-Za-z0-9_])(?:eval|instance_eval|class_eval|module_eval)\s*[\s({]|\bbinding\s*\(\s*\)\.eval\s*\(/;
const RX_NATIVE = /\brequire\s+['"]fiddle['"]|\brequire\s+['"]ffi['"]|\bFiddle::(?:Function|Handle)\b|\bFFI::Library\b/;
const RX_FS_WRITE = /\bFile\.(?:write|open|delete|unlink|rename|truncate)\s*\(|\bFile\.open\s*\([^)]*,\s*['"](?:w|a|r\+|w\+|a\+|wb|ab)['"]|\bFileUtils\.(?:cp|cp_r|mv|rm|rm_rf|mkdir|mkdir_p|chmod|chown|touch)\b|\bIO\.write\s*\(/;
const RX_CRYPTO = /\brequire\s+['"](?:openssl|digest|securerandom)['"]|\bOpenSSL::(?:Cipher|HMAC|Digest|PKey|X509|SSL)\b|\bDigest::(?:MD5|SHA1|SHA256|SHA512)\b/;
const RX_SERDE = /\bMarshal\.(?:load|restore)\s*\(|\bYAML\.(?:load|unsafe_load)\s*\(|\bPsych\.unsafe_load\s*\(|\bJSON\.load\s*\(/;
const RX_DNS = /\brequire\s+['"]resolv['"]|\bResolv\.(?:getaddress|getaddresses|getname)\s*\(|\bSocket\.gethostbyname\s*\(|\bTCPSocket\.gethostbyname\s*\(/;
const RX_WS = /\brequire\s+['"](?:faye-websocket|em-websocket|websocket-client-simple)['"]|\bFaye::WebSocket\b|\bEM::WebSocket\b/;
const RX_SIGNAL = /\bSignal\.(?:trap|list)\s*\(|\bProcess\.(?:kill|wait|detach)\s*\(|\btrap\s*\(\s*['"]SIG[A-Z]+['"]/;
const RX_BASE64 = /\bBase64\.(?:decode64|urlsafe_decode64|strict_decode64)\s*\(\s*['"][A-Za-z0-9+/=_-]{200,}['"]/;
const RX_DYNIMPORT = /\brequire\s+(?!['"])\S+|\bObject\.const_get\s*\(|\b(?:send|__send__|public_send)\s*\(\s*(?!:?['"][\w?!=]+['"])[^)]+\)/;
const RX_ENV = /\bENV\s*\[|\bENV\.(?:fetch|store|to_h|each)\b/;
const RX_CLIPBOARD = /\brequire\s+['"]clipboard['"]|\bClipboard\.(?:copy|paste|implementation)\b/;

export const rubyDetector: CapabilityDetector = {
  language: 'ruby',
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
