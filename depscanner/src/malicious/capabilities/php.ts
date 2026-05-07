/**
 * PHP capability detector. Patterns match the historical PHP malicious-
 * package surface: shell_exec, eval, unserialize, file_put_contents over
 * curl. install_script via composer.json `scripts` handled in manifest.ts.
 */
import type { CapabilityDetector, CapabilitySet } from './types';

const EXTS = ['.php', '.phtml', '.phps', '.php5', '.php7'];

const RX_SPAWNS = /(?:^|[^A-Za-z0-9_])(?:exec|shell_exec|system|passthru|proc_open|popen|pcntl_exec)\s*\(|`[^`]{1,500}`/;
const RX_NETWORK = /\bcurl_(?:init|exec|setopt|setopt_array)\s*\(|\bfile_get_contents\s*\(\s*['"]https?:\/\/|\bfsockopen\s*\(|\bstream_socket_client\s*\(|\bGuzzle(?:Http)?\\Client\b/;
const RX_EVAL = /(?:^|[^A-Za-z0-9_])(?:eval|assert|create_function)\s*\(|\bcall_user_func(?:_array)?\s*\(\s*\$|\b\$\w+\s*\(\s*\)/;
const RX_NATIVE = /(?:^|[^A-Za-z0-9_])dl\s*\(|\bextension_loaded\s*\(|\bopcache_compile_file\s*\(/;
const RX_FS_WRITE = /\bfile_put_contents\s*\(|\bfwrite\s*\(|\bfputs\s*\(|\bfopen\s*\([^)]*,\s*['"](?:w|a|x|c|w\+|a\+|x\+|c\+)['"]|\b(?:unlink|rename|chmod|chown|mkdir|rmdir|symlink|link)\s*\(|\bcopy\s*\(/;
const RX_CRYPTO = /\bopenssl_(?:encrypt|decrypt|sign|verify|public_encrypt|private_decrypt|pkey_new|cipher_iv_length)\s*\(|\bhash(?:_hmac|_pbkdf2)?\s*\(|\bmcrypt_(?:encrypt|decrypt)\s*\(|\bpassword_(?:hash|verify)\s*\(/;
const RX_SERDE = /\bunserialize\s*\(|\byaml_parse(?:_file|_url)?\s*\(|\bphar_extract\b/;
const RX_DNS = /\bgethostbyname\s*\(|\bgethostbynamel\s*\(|\bdns_get_record\s*\(|\bcheckdnsrr\s*\(|\bgetmxrr\s*\(/;
const RX_WS = /\bRatchet\\(?:WebSocket|App)\b|\bswoole_websocket_server\b|\bratchet\/pawl\b/;
const RX_SIGNAL = /\bpcntl_signal\s*\(|\bpcntl_alarm\s*\(|\bposix_kill\s*\(/;
const RX_BASE64 = /\bbase64_decode\s*\(\s*['"][A-Za-z0-9+/=_-]{200,}['"]/;
const RX_DYNIMPORT = /\b(?:include|include_once|require|require_once)\s*\(?\s*\$|\bcall_user_func(?:_array)?\s*\(\s*\$/;
const RX_ENV = /\$_ENV\b|\$_SERVER\b|\bgetenv\s*\(|\bputenv\s*\(/;

export const phpDetector: CapabilityDetector = {
  language: 'php',
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
      clipboard_access: false,
    };
  },
};
