/**
 * Rust capability detector. Rust has no `eval` or run-time dynamic_import,
 * so those tags stay false. install_script via `build.rs` handled in
 * manifest.ts.
 */
import type { CapabilityDetector, CapabilitySet } from './types';

const EXTS = ['.rs'];

const RX_SPAWNS = /\bstd::process::Command\b|\bCommand::new\s*\(|\bduct::cmd!?\s*\(|\bnix::unistd::(?:execv|execve|fork)\b/;
const RX_NETWORK = /\bstd::net::(?:TcpStream|TcpListener|UdpSocket)\b|\breqwest::(?:Client|get|post|blocking)\b|\bhyper::(?:Client|Request|Server)\b|\btokio::net::(?:TcpStream|TcpListener|UdpSocket)\b|\bisahc::(?:get|post)\b|\bcurl::easy::Easy\b/;
const RX_NATIVE = /\blibloading::Library::new\s*\(|\bunsafe\s+extern\s*"C"|\bextern\s+"C"\s*\{|\bstd::dlopen\b/;
const RX_FS_WRITE = /\bstd::fs::(?:write|create_dir|create_dir_all|remove_file|remove_dir|remove_dir_all|rename|set_permissions|copy|hard_link)\s*\(|\bFile::create\s*\(|\bOpenOptions::new\s*\(\s*\)\.[\w.]*write\s*\(\s*true\)|\btokio::fs::(?:write|remove_file|rename|create_dir)\b/;
const RX_CRYPTO = /\bring::(?:aead|digest|hmac|hkdf|signature|rand)\b|\bopenssl::\w+::Crypter\b|\bsha2::(?:Sha256|Sha512|Sha1)\b|\baes::Aes\d+\b|\bargon2::Argon2\b/;
const RX_SERDE = /\bbincode::(?:deserialize|deserialize_from)\s*\(|\bserde_pickle::from_(?:slice|read|reader)\s*\(|\brmp_serde::from_(?:slice|read|read_ref)\s*\(|\bciborium::de::from_reader\s*\(/;
const RX_DNS = /\btrust_dns_resolver::Resolver\b|\btokio::net::lookup_host\s*\(|\bstd::net::ToSocketAddrs\b/;
const RX_WS = /\btokio_tungstenite::(?:connect_async|accept_async)\s*\(|\btungstenite::(?:connect|client|accept)\b|\bwarp::ws\b|\baxum::extract::ws\b/;
const RX_SIGNAL = /\btokio::signal::(?:ctrl_c|unix::signal)\b|\bnix::sys::signal::(?:kill|raise|signal)\b|\bsignal_hook::(?:flag|consts|iterator)\b/;
const RX_BASE64 = /\bbase64::(?:decode|decode_config|engine::general_purpose::STANDARD\.decode)\s*\(\s*"[A-Za-z0-9+/=_-]{200,}"/;
const RX_ENV = /\bstd::env::(?:var|var_os|vars|vars_os|set_var|remove_var)\s*\(/;
const RX_CLIPBOARD = /\barboard::Clipboard\b|\bclipboard::ClipboardContext\b|\bcopypasta::ClipboardContext\b/;

export const rustDetector: CapabilityDetector = {
  language: 'rust',
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
