declare module '@dagrejs/dagre' {
  export namespace graphlib {
    class Graph {
      constructor(opts?: { directed?: boolean; multigraph?: boolean; compound?: boolean });
      setDefaultEdgeLabel(callback: () => object): void;
      setGraph(label: {
        rankdir?: string;
        nodesep?: number;
        ranksep?: number;
        marginx?: number;
        marginy?: number;
      }): void;
      setNode(name: string, label: { width: number; height: number }): void;
      setEdge(source: string, target: string): void;
      node(name: string): { x: number; y: number; width: number; height: number };
    }
  }
  export function layout(graph: graphlib.Graph): void;
}
