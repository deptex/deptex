/**
 * C# capability detector. Patterns target the .NET BCL + Roslyn scripting
 * surface. install_script via NuGet `tools/init.ps1` handled in manifest.ts.
 */
import type { CapabilityDetector, CapabilitySet } from './types';

const EXTS = ['.cs', '.csx'];

const RX_SPAWNS = /\bSystem\.Diagnostics\.Process\.Start\s*\(|\bnew\s+Process(?:StartInfo)?\s*\(|\bProcess\.Start\s*\(/;
const RX_NETWORK = /\bnew\s+(?:HttpClient|WebClient|TcpClient|UdpClient|Socket)\s*\(|\bWebRequest\.(?:Create|CreateHttp)\s*\(|\bSystem\.Net\.Http\.HttpClient\b|\bRestSharp\.RestClient\b/;
const RX_EVAL = /\bCSharpScript\.(?:EvaluateAsync|RunAsync|Run|Eval(?:uateAsync)?)\b|\bMicrosoft\.CodeAnalysis\.CSharp\.Scripting\b|\bSystem\.Linq\.Expressions\.LambdaExpression\.Compile\s*\(/;
const RX_NATIVE = /\[\s*DllImport\s*\(|\bAssembly\.(?:LoadFile|LoadFrom|Load)\s*\(|\bAppDomain\.CurrentDomain\.Load\s*\(/;
const RX_FS_WRITE = /\bFile\.(?:WriteAllText|WriteAllBytes|WriteAllLines|AppendAllText|AppendAllLines|Delete|Move|Copy|Create|CreateText|Open(?:Write)?|SetAttributes|SetLastWriteTime)\s*\(|\bnew\s+FileStream\s*\([^)]*FileMode\.(?:Create|Append|Truncate|OpenOrCreate)\b|\bDirectory\.(?:Create|Delete|Move)Directory\s*\(/;
const RX_CRYPTO = /\bSystem\.Security\.Cryptography\.\w+\b|\bAes\.Create\s*\(|\bRSA\.Create\s*\(|\bSHA(?:1|256|384|512)\.Create\s*\(|\bMD5\.Create\s*\(|\bRandomNumberGenerator\.Create\s*\(/;
const RX_SERDE = /\bBinaryFormatter\b\s*\.\s*Deserialize\s*\(|\bnew\s+SoapFormatter\b|\bDataContractSerializer\b\s*\.\s*ReadObject\s*\(|\bXmlSerializer\b\s*\.\s*Deserialize\s*\(|\bNetDataContractSerializer\b/;
const RX_DNS = /\bSystem\.Net\.Dns\.(?:GetHostEntry|GetHostAddresses|BeginGetHostEntry)\s*\(/;
const RX_WS = /\bnew\s+ClientWebSocket\s*\(|\bSystem\.Net\.WebSockets\.\w+\b|\bSignalR\.HubConnection\b/;
const RX_SIGNAL = /\bConsole\.CancelKeyPress\b|\bAppDomain\.CurrentDomain\.ProcessExit\b|\bProcess\.Kill\s*\(|\bAppDomain\.CurrentDomain\.UnhandledException\b/;
const RX_BASE64 = /\bConvert\.FromBase64String\s*\(\s*"[A-Za-z0-9+/=]{200,}"/;
const RX_DYNIMPORT = /\bType\.GetType\s*\(\s*(?!"[\w.,= +]+")[^)]+\)|\bActivator\.CreateInstance\s*\(\s*(?!typeof)[^)]+\)/;
const RX_ENV = /\bEnvironment\.(?:GetEnvironmentVariable|GetEnvironmentVariables|GetCommandLineArgs|UserName|MachineName)\b/;
const RX_CLIPBOARD = /\bSystem\.Windows\.(?:Forms\.)?Clipboard\.(?:SetText|GetText|SetData|GetData)\s*\(|\bWindows\.ApplicationModel\.DataTransfer\.Clipboard\b/;

export const csharpDetector: CapabilityDetector = {
  language: 'csharp',
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
