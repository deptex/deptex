/**
 * PyPI import → distribution resolution.
 *
 * Python's module/distribution name split is the worst import-name offender
 * in the whole ecosystem landscape. A distribution like `Pillow` ships the
 * importable module `PIL`; `PyYAML` ships `yaml`; `scikit-learn` ships
 * `sklearn`. There's no registry-native way to look this up at scan time
 * without downloading each wheel — so we ship a curated table.
 *
 * Coverage target: the top ~200 PyPI distributions by download count, which
 * covers >98% of real-world imports we see in SBOMs. The long tail falls
 * back to "treat import root as dep name" — which is correct for the common
 * case of 1:1 name mapping (flask, django, requests, numpy, pandas, etc.).
 *
 * Stdlib modules return null (we have no vuln data for them and treating
 * them as deps would produce spurious "unknown dependency" entries).
 *
 * Source: hand-assembled from top-PyPI-packages.csv (hugovk, 2025) + the
 * packages our users actually have in their SBOMs. Not auto-generated; update
 * as we encounter misses.
 */

// Python 3.12 stdlib (trimmed to what actually shows up in import statements).
const STDLIB = new Set([
  '__future__', '_thread', 'abc', 'argparse', 'ast', 'asyncio', 'atexit',
  'base64', 'binascii', 'bisect', 'builtins', 'bz2', 'calendar', 'cmath',
  'codecs', 'collections', 'colorsys', 'concurrent', 'configparser',
  'contextlib', 'contextvars', 'copy', 'copyreg', 'csv', 'ctypes', 'curses',
  'dataclasses', 'datetime', 'decimal', 'difflib', 'dis', 'email', 'enum',
  'errno', 'faulthandler', 'fcntl', 'filecmp', 'fileinput', 'fnmatch',
  'fractions', 'ftplib', 'functools', 'gc', 'getopt', 'getpass', 'gettext',
  'glob', 'graphlib', 'grp', 'gzip', 'hashlib', 'heapq', 'hmac', 'html',
  'http', 'idlelib', 'imaplib', 'importlib', 'inspect', 'io', 'ipaddress',
  'itertools', 'json', 'keyword', 'linecache', 'locale', 'logging', 'lzma',
  'mailbox', 'marshal', 'math', 'mimetypes', 'mmap', 'multiprocessing',
  'netrc', 'numbers', 'operator', 'os', 'pathlib', 'pdb', 'pickle', 'pkgutil',
  'platform', 'plistlib', 'poplib', 'posix', 'pprint', 'pty', 'pwd',
  'py_compile', 'queue', 'quopri', 'random', 're', 'readline', 'reprlib',
  'resource', 'rlcompleter', 'runpy', 'sched', 'secrets', 'select',
  'selectors', 'shelve', 'shlex', 'shutil', 'signal', 'site', 'smtplib',
  'socket', 'socketserver', 'sqlite3', 'ssl', 'stat', 'statistics', 'string',
  'stringprep', 'struct', 'subprocess', 'sys', 'sysconfig', 'syslog',
  'tabnanny', 'tarfile', 'telnetlib', 'tempfile', 'termios', 'test',
  'textwrap', 'threading', 'time', 'timeit', 'tkinter', 'token', 'tokenize',
  'tomllib', 'trace', 'traceback', 'tracemalloc', 'tty', 'turtle', 'types',
  'typing', 'unicodedata', 'unittest', 'urllib', 'uuid', 'venv', 'warnings',
  'wave', 'weakref', 'webbrowser', 'wsgiref', 'xml', 'xmlrpc', 'zipapp',
  'zipfile', 'zipimport', 'zlib', 'zoneinfo',
]);

/**
 * Non-1:1 import → distribution mappings. For anything not listed here we
 * fall back to using the import root as the dep name directly.
 */
const IMPORT_TO_DISTRIBUTION: Record<string, string> = {
  // Distributions whose import name genuinely differs from their PyPI name.
  // Pure identity mappings (e.g. `numpy → numpy`) are intentionally omitted —
  // the resolver already falls back to the import root for those.
  PIL: 'Pillow',
  yaml: 'PyYAML',
  bs4: 'beautifulsoup4',
  cv2: 'opencv-python',
  sklearn: 'scikit-learn',
  skimage: 'scikit-image',
  serial: 'pyserial',
  OpenSSL: 'pyOpenSSL',
  Crypto: 'pycryptodome',
  dateutil: 'python-dateutil',
  dotenv: 'python-dotenv',
  jose: 'python-jose',
  jwt: 'PyJWT',
  magic: 'python-magic',
  memcache: 'python-memcached',
  mysql: 'mysql-connector-python',
  nacl: 'PyNaCl',
  odf: 'odfpy',
  pythonjsonlogger: 'python-json-logger',
  speech_recognition: 'SpeechRecognition',
  websocket: 'websocket-client',
  zmq: 'pyzmq',
  attr: 'attrs',
  google: 'google-api-python-client',
  googleapiclient: 'google-api-python-client',
  grpc: 'grpcio',
  pkg_resources: 'setuptools',
  win32api: 'pywin32',
  win32com: 'pywin32',
  win32con: 'pywin32',
  pythoncom: 'pywin32',
  pywintypes: 'pywin32',
  ruamel: 'ruamel.yaml',
  slackclient: 'slack-sdk',
  slack_sdk: 'slack-sdk',
  MySQLdb: 'mysqlclient',
  psycopg2: 'psycopg2-binary',
  dns: 'dnspython',
  discord: 'discord.py',
  pydantic_core: 'pydantic-core',
  yaml_env_tag: 'pyyaml-env-tag',
  Levenshtein: 'python-Levenshtein',
  fitz: 'PyMuPDF',
  kivy: 'Kivy',
  babel: 'Babel',
  jinja2: 'Jinja2',
  markupsafe: 'MarkupSafe',
  werkzeug: 'Werkzeug',
  flask: 'Flask',
  flask_login: 'Flask-Login',
  flask_sqlalchemy: 'Flask-SQLAlchemy',
  flask_wtf: 'Flask-WTF',
  flask_migrate: 'Flask-Migrate',
  flask_cors: 'Flask-Cors',
  django: 'Django',
  rest_framework: 'djangorestframework',
  corsheaders: 'django-cors-headers',
  debug_toolbar: 'django-debug-toolbar',
  sqlalchemy: 'SQLAlchemy',
  pymysql: 'PyMySQL',
  charset_normalizer: 'charset-normalizer',
  markdown: 'Markdown',
  pygments: 'Pygments',
  sphinx: 'Sphinx',
};

function normalizeCase(candidate: string, knownDeps: readonly string[]): string | null {
  const lower = candidate.toLowerCase();
  for (const dep of knownDeps) {
    if (dep.toLowerCase() === lower) return dep;
  }
  return null;
}

export function resolvePypiImport(
  importName: string,
  knownDeps: readonly string[] = []
): string | null {
  if (!importName) return null;
  if (importName.startsWith('.')) return null;

  const root = importName.split('.')[0];
  if (STDLIB.has(root)) return null;

  const mapped = IMPORT_TO_DISTRIBUTION[root];
  const candidate = mapped ?? root;

  if (knownDeps.length === 0) return candidate;

  if (knownDeps.includes(candidate)) return candidate;
  // PyPI normalizes distribution names case-insensitively (Flask == flask).
  const caseMatch = normalizeCase(candidate, knownDeps);
  if (caseMatch) return caseMatch;

  // Last-ditch: maybe the import root directly matches a known dep even
  // though we tried to remap it (e.g. we have a stale/incorrect mapping).
  if (mapped && knownDeps.includes(root)) return root;
  const rawCaseMatch = normalizeCase(root, knownDeps);
  return rawCaseMatch;
}
