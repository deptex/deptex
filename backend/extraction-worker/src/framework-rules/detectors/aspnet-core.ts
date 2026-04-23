import type { Node } from 'web-tree-sitter';
import type { DetectorContext, EntryPoint, FrameworkDetector, HttpMethod } from '../types';

function textOf(n: Node | null, src: string): string {
  return n ? src.slice(n.startIndex, n.endIndex) : '';
}

function csStringLiteral(node: Node | null, source: string): string | null {
  if (!node || node.type !== 'string_literal') return null;
  for (let i = 0; i < node.namedChildCount; i++) {
    const c = node.namedChild(i)!;
    if (c.type === 'string_literal_content' || c.type === 'string_content') return textOf(c, source);
  }
  const raw = textOf(node, source);
  const m = raw.match(/^"(.*)"$/s);
  return m ? m[1] : null;
}

// ASP.NET Core controllers:
//   [ApiController]
//   [Route("api/[controller]")]
//   public class UsersController : ControllerBase {
//     [HttpGet("{id}")] public string Get(int id) { ... }
//     [HttpPost]        public string Create() { ... }
//     [Route("search")] [HttpGet] public ...
//   }

const HTTP_ATTRIBUTE_VERBS: Record<string, HttpMethod> = {
  HttpGet: 'GET', HttpPost: 'POST', HttpPut: 'PUT', HttpPatch: 'PATCH',
  HttpDelete: 'DELETE', HttpHead: 'HEAD', HttpOptions: 'OPTIONS',
};

export const aspnetCoreDetector: FrameworkDetector = {
  name: 'aspnet-core',
  displayName: 'ASP.NET Core',
  language: 'csharp',
  triggerImports: ['Microsoft.AspNetCore.Mvc'],
  detect(ctx: DetectorContext): EntryPoint[] {
    const { tree, file, source } = ctx;
    const entryPoints: EntryPoint[] = [];

    const walk = (node: Node): void => {
      if (node.type === 'class_declaration') {
        const classAttrs = attributesOn(node, source);
        const classRoute = firstStringFromAttributeNamed(classAttrs, 'Route', source);
        const isController = classAttrs.some((a) => a.name === 'ApiController') ||
          (node.childForFieldName('name') && /Controller$/.test(textOf(node.childForFieldName('name'), source)));

        if (!isController && !classRoute) {
          // Fall through to children (nested classes).
        } else {
          const body = node.childForFieldName('body');
          if (body) {
            for (let i = 0; i < body.namedChildCount; i++) {
              const member = body.namedChild(i)!;
              if (member.type !== 'method_declaration') continue;
              const methodAttrs = attributesOn(member, source);
              const methodName = member.childForFieldName('name');
              const handlerName = methodName ? textOf(methodName, source) : null;

              const routeOnMethod = firstStringFromAttributeNamed(methodAttrs, 'Route', source);

              for (const attr of methodAttrs) {
                const verb = HTTP_ATTRIBUTE_VERBS[attr.name];
                if (!verb) continue;
                const verbPath = attr.firstStringArg;
                const subPath = verbPath ?? routeOnMethod ?? '';
                entryPoints.push({
                  filePath: file.filePath,
                  lineNumber: member.startPosition.row + 1,
                  framework: 'aspnet-core',
                  handlerName,
                  httpMethod: verb,
                  routePattern: joinRoute(classRoute, subPath),
                  entryPointType: 'http_route',
                  classification: 'PUBLIC_UNAUTH',
                  authenticated: null,
                  authMechanism: null,
                  middlewareChain: null,
                  metadata: { attribute: attr.name },
                });
              }
            }
          }
        }
      }
      for (let i = 0; i < node.namedChildCount; i++) walk(node.namedChild(i)!);
    };
    walk(tree.rootNode);
    return entryPoints;
  },
};

interface ParsedAttribute { name: string; firstStringArg: string | null; }

function attributesOn(decl: Node, source: string): ParsedAttribute[] {
  const out: ParsedAttribute[] = [];
  for (let i = 0; i < decl.namedChildCount; i++) {
    const child = decl.namedChild(i)!;
    if (child.type !== 'attribute_list') continue;
    for (let j = 0; j < child.namedChildCount; j++) {
      const attr = child.namedChild(j)!;
      if (attr.type !== 'attribute') continue;
      const name = attr.childForFieldName('name') ?? attr.namedChild(0);
      if (!name) continue;
      const nameText = textOf(name, source);
      const args = attr.childForFieldName('arguments') ?? attr.namedChild(1);
      let firstStringArg: string | null = null;
      if (args) {
        for (let k = 0; k < args.namedChildCount; k++) {
          const arg = args.namedChild(k)!;
          const inner = arg.type === 'attribute_argument' ? arg.namedChild(0) : arg;
          if (inner?.type === 'string_literal') {
            firstStringArg = csStringLiteral(inner, source);
            break;
          }
        }
      }
      out.push({ name: nameText, firstStringArg });
    }
  }
  return out;
}

function firstStringFromAttributeNamed(attrs: ParsedAttribute[], name: string, _source: string): string | null {
  const hit = attrs.find((a) => a.name === name);
  return hit?.firstStringArg ?? null;
}

function joinRoute(prefix: string | null, sub: string | null): string | null {
  if (!prefix && !sub) return null;
  const p = prefix ? (prefix.startsWith('/') ? prefix : `/${prefix}`).replace(/\/$/, '') : '';
  const s = sub ? (sub.startsWith('/') ? sub : `/${sub}`) : '';
  return (`${p}${s}` || '/').replace(/\/+/g, '/');
}
