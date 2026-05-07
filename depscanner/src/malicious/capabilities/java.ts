/**
 * Java capability detector. Pattern set targets the JDK + popular crypto /
 * networking libraries. Capability scan is light-touch on Java because
 * malicious-package distribution via Maven is rarer than via npm/PyPI.
 */
import type { CapabilityDetector, CapabilitySet } from './types';

const EXTS = ['.java'];

const RX_SPAWNS = /\bRuntime\.getRuntime\(\)\.exec\s*\(|\bnew\s+ProcessBuilder\s*\(/;
const RX_NETWORK = /\bnew\s+(?:URL|URI)\s*\([^)]+\)\.openConnection|\bjava\.net\.HttpURLConnection|\bHttpClient\.newBuilder|\bHttpRequest\.newBuilder|\bnew\s+Socket\s*\(|\bokhttp3\.OkHttpClient/;
const RX_EVAL = /\bScriptEngineManager\b|\bScriptEngine\b\s*\.\s*eval\s*\(|\bjavax\.script\b/;
const RX_NATIVE = /\bSystem\.loadLibrary\s*\(|\bSystem\.load\s*\(|\bRuntime\.getRuntime\(\)\.load(?:Library)?\s*\(/;
const RX_FS_WRITE = /\bnew\s+(?:FileOutputStream|FileWriter|PrintWriter|BufferedWriter)\s*\(|\bFiles\.(?:write|writeString|copy|move|delete|deleteIfExists|createDirectory|createDirectories|createFile)\s*\(/;
const RX_CRYPTO = /\bjavax\.crypto\b|\bjava\.security\.(?:MessageDigest|Signature|KeyPairGenerator|SecureRandom)\b|\bMessageDigest\.getInstance\s*\(|\bCipher\.getInstance\s*\(/;
const RX_SERDE = /\bnew\s+ObjectInputStream\s*\([^)]*\)\.readObject\s*\(|\bXMLDecoder\b\s*\.\s*readObject\s*\(|\borg\.yaml\.snakeyaml\.Yaml\b/;
const RX_DNS = /\bInetAddress\.(?:getByName|getAllByName|getByAddress)\s*\(|\bjavax\.naming\.directory\.InitialDirContext\b/;
const RX_WS = /\bjavax\.websocket\b|\bWebSocketClient\b|\bSpring(?:WebSocket|WebSocketClient)\b|\borg\.eclipse\.jetty\.websocket\b/;
const RX_SIGNAL = /\bRuntime\.getRuntime\(\)\.addShutdownHook\b|\bProcess\.destroy(?:Forcibly)?\s*\(|\bsun\.misc\.Signal\b/;
const RX_BASE64 = /\bBase64\.getDecoder\(\)\.decode\s*\(\s*"[A-Za-z0-9+/=]{200,}"|\bDatatypeConverter\.parseBase64Binary\s*\(\s*"[A-Za-z0-9+/=]{200,}"/;
const RX_DYNIMPORT = /\bClass\.forName\s*\(\s*(?!"[\w.$]+")[^)]+\)|\bClassLoader\b\s*\.\s*loadClass\s*\(\s*(?!"[\w.$]+")[^)]+\)/;
const RX_ENV = /\bSystem\.getenv\s*\(|\bSystem\.getProperty\s*\(/;
const RX_CLIPBOARD = /\bToolkit\.getDefaultToolkit\(\)\.getSystemClipboard\b|\bjava\.awt\.datatransfer\.Clipboard\b/;

export const javaDetector: CapabilityDetector = {
  language: 'java',
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
