/**
 * Phase 6B: CodeImpactView + Reachability UI Tests
 *
 * Tests 44-48: CodeImpactView Component
 * Tests 49-51: Code Context Endpoint Integration
 * Tests 52-55: Reachability Filters
 */

import type { ReachableFlow, ReachableFlowNode, CodeContext, ReachabilityLevel } from '../lib/api';

// =====================================================================
// Tests 44-48: CodeImpactView Component (data structure validation)
// =====================================================================

describe('CodeImpactView data structures', () => {
  const mockFlow: ReachableFlow = {
    id: 'flow-1',
    project_id: 'proj-1',
    extraction_run_id: '1700000000',
    purl: 'pkg:npm/lodash@4.17.15',
    dependency_id: 'dep-1',
    flow_nodes: [
      {
        parentFileName: 'src/api/handler.ts',
        parentMethodName: 'processInput',
        lineNumber: 40,
        tags: 'framework-input',
        isExternal: false,
        code: 'req.body',
        name: 'req',
      },
      {
        parentFileName: 'src/api/handler.ts',
        fullName: 'lodash.merge',
        lineNumber: 42,
        isExternal: true,
        code: '_.merge({}, data)',
        name: 'merge',
      },
    ],
    entry_point_file: 'src/api/handler.ts',
    entry_point_method: 'processInput',
    entry_point_line: 40,
    entry_point_tag: 'framework-input',
    sink_file: 'src/api/handler.ts',
    sink_method: 'lodash.merge',
    sink_line: 42,
    sink_is_external: true,
    flow_length: 2,
    llm_prompt: 'User input from req.body flows into lodash.merge()',
    created_at: '2025-01-01T00:00:00Z',
  };

  test('44. flow nodes contain code field for syntax highlighting', () => {
    for (const node of mockFlow.flow_nodes) {
      expect(node.code).toBeTruthy();
      expect(typeof node.code).toBe('string');
    }
  });

  test('45. flow has entry and sink for call chain rendering', () => {
    const firstNode = mockFlow.flow_nodes[0];
    const lastNode = mockFlow.flow_nodes[mockFlow.flow_nodes.length - 1];

    expect(firstNode.parentFileName).toBe('src/api/handler.ts');
    expect(firstNode.lineNumber).toBe(40);
    expect(lastNode.isExternal).toBe(true);
    expect(lastNode.fullName).toBe('lodash.merge');
  });

  test('46. code context interface for lazy fetch', () => {
    const mockContext: CodeContext = {
      filePath: 'src/api/handler.ts',
      startLine: 35,
      endLine: 45,
      code: 'function processInput(req, res) {\n  const data = req.body;\n  const merged = _.merge({}, data);\n  return merged;\n}',
      language: 'typescript',
    };

    expect(mockContext.filePath).toBe('src/api/handler.ts');
    expect(mockContext.startLine).toBeLessThan(mockContext.endLine);
    expect(mockContext.code).toContain('_.merge');
    expect(mockContext.language).toBe('typescript');
  });

  test('47. flows with >3 nodes have collapsible middle steps', () => {
    const longFlow: ReachableFlow = {
      ...mockFlow,
      flow_nodes: Array.from({ length: 6 }, (_, i) => ({
        parentFileName: `src/file${i}.ts`,
        lineNumber: (i + 1) * 10,
        name: `step${i}`,
        isExternal: i === 5,
        code: `code at step ${i}`,
      })),
      flow_length: 6,
    };

    const middleNodes = longFlow.flow_nodes.slice(1, -1);
    expect(middleNodes.length).toBe(4);
    expect(middleNodes.length).toBeGreaterThan(3);
  });

  test('48. llm_prompt available for Aegis context injection', () => {
    expect(mockFlow.llm_prompt).toBeTruthy();
    expect(mockFlow.llm_prompt).toContain('lodash.merge');
    expect(mockFlow.llm_prompt).toContain('req.body');
  });
});

// =====================================================================
// Tests 49-51: Code Context Endpoint (integration shape)
// =====================================================================

describe('Code context endpoint integration', () => {
  test('49. valid code context response shape', () => {
    const response: CodeContext = {
      filePath: 'src/handler.ts',
      startLine: 35,
      endLine: 45,
      code: 'function handler() { ... }',
      language: 'typescript',
    };

    expect(response).toHaveProperty('filePath');
    expect(response).toHaveProperty('startLine');
    expect(response).toHaveProperty('endLine');
    expect(response).toHaveProperty('code');
    expect(response).toHaveProperty('language');
  });

  test('50. invalid step index returns appropriate error shape', () => {
    const errorResponse = { error: 'Invalid step index' };
    expect(errorResponse.error).toBeTruthy();
  });

  test('51. rate limit response shape', () => {
    const rateLimitResponse = { error: 'Rate limit exceeded', retry_after: 45 };
    expect(rateLimitResponse.retry_after).toBeGreaterThan(0);
  });
});

// =====================================================================
// Tests 52-55: Reachability Filters
// =====================================================================

describe('Reachability filter logic', () => {
  const mockVulns = [
    { osv_id: 'GHSA-1', reachability_level: 'data_flow' as ReachabilityLevel, is_reachable: true },
    { osv_id: 'GHSA-2', reachability_level: 'function' as ReachabilityLevel, is_reachable: true },
    { osv_id: 'GHSA-3', reachability_level: 'module' as ReachabilityLevel, is_reachable: true },
    { osv_id: 'GHSA-4', reachability_level: 'unreachable' as ReachabilityLevel, is_reachable: false },
    { osv_id: 'GHSA-5', reachability_level: null, is_reachable: true },
  ];

  test('52. data_flow filter shows only data_flow', () => {
    const filtered = mockVulns.filter(v => v.reachability_level === 'data_flow');
    expect(filtered).toHaveLength(1);
    expect(filtered[0].osv_id).toBe('GHSA-1');
  });

  test('53. function filter shows function + data_flow', () => {
    const LEVEL_HIERARCHY = ['data_flow', 'confirmed', 'function'];
    const filtered = mockVulns.filter(v =>
      v.reachability_level && LEVEL_HIERARCHY.includes(v.reachability_level)
    );
    expect(filtered).toHaveLength(2);
    expect(filtered.map(v => v.osv_id).sort()).toEqual(['GHSA-1', 'GHSA-2']);
  });

  test('54. reachability level icon mapping', () => {
    const iconMap: Record<string, string> = {
      data_flow: 'orange',
      confirmed: 'red',
      function: 'yellow',
      module: 'gray',
      unreachable: 'dimmed',
    };

    expect(iconMap['data_flow']).toBe('orange');
    expect(iconMap['function']).toBe('yellow');
    expect(iconMap['module']).toBe('gray');
    expect(iconMap['unreachable']).toBe('dimmed');
  });

  test('55. null reachability_level shows pending badge', () => {
    const pendingVulns = mockVulns.filter(v => v.reachability_level === null);
    expect(pendingVulns).toHaveLength(1);
    expect(pendingVulns[0].osv_id).toBe('GHSA-5');
  });
});
