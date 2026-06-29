import { urlHeadIsConstant } from './url-host';

const noResolve = () => undefined;

describe('urlHeadIsConstant', () => {
  describe('constant host → true (suppress SSRF/open-redirect FP)', () => {
    it('inline template literal with literal host + tainted path', () => {
      expect(urlHeadIsConstant('`https://api.github.com/repos/${repo}`', noResolve)).toBe(true);
    });
    it('inline string literal host', () => {
      expect(urlHeadIsConstant("'https://registry.npmjs.org/lodash'", noResolve)).toBe(true);
    });
    it('http (not https) literal host', () => {
      expect(urlHeadIsConstant('`http://localhost:3001/x/${id}`', noResolve)).toBe(true);
    });
    it('bare var resolving to a literal-host template', () => {
      const resolve = (n: string) =>
        n === 'registryUrl' ? '`https://registry.npmjs.org/${enc}`' : undefined;
      expect(urlHeadIsConstant('registryUrl', resolve)).toBe(true);
    });
    it('template whose head is a const-resolved base URL (module const)', () => {
      const resolve = (n: string) =>
        n === 'GITHUB_API_BASE' ? "'https://api.github.com'" : undefined;
      expect(urlHeadIsConstant('`${GITHUB_API_BASE}/app/installations/${id}`', resolve)).toBe(true);
    });
    it('two-level: url var → template → base const', () => {
      const resolve = (n: string) => {
        if (n === 'url') return '`${BASE}/repos/${repo}`';
        if (n === 'BASE') return "'https://api.github.com'";
        return undefined;
      };
      expect(urlHeadIsConstant('url', resolve)).toBe(true);
    });
  });

  describe('tainted / unknown host → false (keep the flow)', () => {
    it('bare identifier with no resolution (could be a user URL)', () => {
      expect(urlHeadIsConstant('userSuppliedUrl', noResolve)).toBe(false);
    });
    it('scheme constant but host concatenated from a variable', () => {
      expect(urlHeadIsConstant("'https://' + attackerHost", noResolve)).toBe(false);
    });
    it('template whose host segment is the first interpolation of a param', () => {
      // `${baseUrl.replace(...)}` — not a bare ident, cannot resolve → keep.
      expect(urlHeadIsConstant('`${baseUrl.replace(/\\/+$/, "")}/projects`', noResolve)).toBe(false);
    });
    it('template whose first interpolation resolves to a non-URL value', () => {
      const resolve = (n: string) => (n === 'prefix' ? "'/api/v2'" : undefined);
      expect(urlHeadIsConstant('`${prefix}/${x}`', resolve)).toBe(false);
    });
    it('empty / whitespace', () => {
      expect(urlHeadIsConstant('', noResolve)).toBe(false);
      expect(urlHeadIsConstant('   ', noResolve)).toBe(false);
    });
    it('object-literal arg (axios config) is not a constant host', () => {
      expect(urlHeadIsConstant('{ url: req.query.target }', noResolve)).toBe(false);
    });
    it('does not infinite-loop on a self-referential resolver', () => {
      const resolve = (n: string) => (n === 'a' ? 'b' : n === 'b' ? 'a' : undefined);
      expect(urlHeadIsConstant('a', resolve)).toBe(false);
    });
  });
});
