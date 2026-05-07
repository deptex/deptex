/**
 * Go capability detector. Patterns match the Go stdlib + popular networking
 * libraries. Note: Go has no `eval` / `dynamic_import` so those tags stay
 * false. cgo via `import "C"` and `plugin.Open` cover native loading.
 */
import type { CapabilityDetector, CapabilitySet } from './types';

const EXTS = ['.go'];

const RX_SPAWNS = /\bos\/exec\b|\bexec\.Command(?:Context)?\s*\(|\bsyscall\.Exec\s*\(|\bsyscall\.ForkExec\s*\(/;
const RX_NETWORK = /\bnet\/http\b|\bhttp\.(?:Get|Post|NewRequest|Client|DefaultClient|DefaultTransport)\b|\bnet\.(?:Dial|DialTCP|Listen|ListenTCP)\b|\bgrpc\.Dial\s*\(/;
const RX_NATIVE = /\bplugin\.Open\s*\(|^\s*import\s+"C"|\b#include\s*</m;
const RX_FS_WRITE = /\bos\.(?:WriteFile|Create|Truncate|Remove|RemoveAll|Rename|Mkdir|MkdirAll|Chmod|Chown)\s*\(|\bioutil\.WriteFile\s*\(|\bbufio\.NewWriter\s*\(/;
const RX_CRYPTO = /\bcrypto\/(?:aes|cipher|des|dsa|ecdsa|ed25519|elliptic|hmac|md5|rand|rc4|rsa|sha1|sha256|sha512|tls|x509)\b/;
const RX_SERDE = /\bencoding\/gob\b|\bgob\.NewDecoder\b|\byaml\.Unmarshal\s*\(|\bbson\.Unmarshal\s*\(/;
const RX_DNS = /\bnet\.(?:LookupHost|LookupIP|LookupAddr|LookupCNAME|LookupMX|LookupNS|LookupTXT|LookupSRV|Resolver)\b/;
const RX_WS = /\bgithub\.com\/gorilla\/websocket\b|\bnhooyr\.io\/websocket\b|\bgolang\.org\/x\/net\/websocket\b/;
const RX_SIGNAL = /\bos\/signal\b|\bsignal\.Notify\s*\(|\bsignal\.Stop\s*\(|\b(?:os\.)?Process\.Kill\s*\(|\bsyscall\.Kill\s*\(/;
const RX_BASE64 = /\bbase64\.(?:StdEncoding|RawStdEncoding|URLEncoding|RawURLEncoding)\.DecodeString\s*\(\s*"[A-Za-z0-9+/=_-]{200,}"/;
const RX_ENV = /\bos\.(?:Getenv|Environ|LookupEnv|Setenv)\s*\(/;
const RX_CLIPBOARD = /\bgithub\.com\/atotto\/clipboard\b|\bgolang\.design\/x\/clipboard\b/;

export const goDetector: CapabilityDetector = {
  language: 'go',
  supportsFile(p) {
    return EXTS.some((e) => p.endsWith(e));
  },
  detect(source): Partial<CapabilitySet> {
    return {
      spawns_processes: RX_SPAWNS.test(source),
      network_io: RX_NETWORK.test(source),
      eval_dynamic: false,
      native_addon_load: RX_NATIVE.test(source),
      filesystem_write: RX_FS_WRITE.test(source),
      crypto_operations: RX_CRYPTO.test(source),
      serialization_deser: RX_SERDE.test(source),
      dns_query: RX_DNS.test(source),
      websocket: RX_WS.test(source),
      process_signal: RX_SIGNAL.test(source),
      encrypted_payload: RX_BASE64.test(source),
      dynamic_import: false,
      reads_env: RX_ENV.test(source),
      clipboard_access: RX_CLIPBOARD.test(source),
    };
  },
};
