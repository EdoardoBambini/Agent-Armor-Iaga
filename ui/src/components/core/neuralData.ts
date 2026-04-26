import type { AIState } from "../../store/useVisualStore";

export interface ClusterDef {
  id: string;
  label: string;
  subtitle: string;
  position: [number, number, number];
  labelOffset: [number, number];
  edgeColor: string;
  nodeColor: string;
  pulseColor: string;
  borderColor: string;
  neuronCount: number;
  firingRate: number;
}

export const SCENE_BACKGROUND = "#000000";
export const FILAMENT_ORIGIN_RADIUS = 0.36;
const NETWORK_SPREAD = 1.18;

const position = (x: number, y: number, z: number): [number, number, number] => [
  x * NETWORK_SPREAD,
  y * NETWORK_SPREAD,
  z * NETWORK_SPREAD,
];

export const CLUSTERS: ClusterDef[] = [
  {
    id: "session_graph",
    label: "L1 SESSION GRAPH",
    subtitle: "Reconstructs action flow and flags suspicious same-session chains before they escalate.",
    position: position(-1.55, 3.65, 0.35),
    labelOffset: [-108, -90],
    edgeColor: "#1a2a10",
    nodeColor: "#88cc33",
    pulseColor: "#bbff44",
    borderColor: "#ff6688",
    neuronCount: 148,
    firingRate: 0.85,
  },
  {
    id: "taint_tracking",
    label: "L2 TAINT TRACKING",
    subtitle: "Tracks sensitive data to every sink to stop exfiltration paths and unsafe transfers.",
    position: position(-4.05, 0.45, 1.12),
    labelOffset: [-132, -10],
    edgeColor: "#1a2208",
    nodeColor: "#99bb22",
    pulseColor: "#ccee33",
    borderColor: "#ddcc00",
    neuronCount: 360,
    firingRate: 0.45,
  },
  {
    id: "nhi_identity",
    label: "L3 NHI IDENTITY",
    subtitle: "Validates workload identity, attestation, and execution trust before action continues.",
    position: position(-2.38, -3.08, 0.9),
    labelOffset: [-124, 70],
    edgeColor: "#0c2208",
    nodeColor: "#66cc44",
    pulseColor: "#88ff55",
    borderColor: "#44ff88",
    neuronCount: 100,
    firingRate: 0.95,
  },
  {
    id: "adaptive_risk",
    label: "L4 ADAPTIVE RISK",
    subtitle: "Combines signals, context, and history into the runtime risk score for each action.",
    position: position(1.85, 0.72, 1.55),
    labelOffset: [94, -46],
    edgeColor: "#220810",
    nodeColor: "#dd3344",
    pulseColor: "#ff5566",
    borderColor: "#ff3344",
    neuronCount: 200,
    firingRate: 0.85,
  },
  {
    id: "sandbox",
    label: "L5 SANDBOX",
    subtitle: "Simulates operational impact before execution to estimate likely blast radius.",
    position: position(-4.35, -2.45, -0.55),
    labelOffset: [-138, 48],
    edgeColor: "#0a1228",
    nodeColor: "#4477aa",
    pulseColor: "#5599cc",
    borderColor: "#3366ff",
    neuronCount: 160,
    firingRate: 0.35,
  },
  {
    id: "policy_engine",
    label: "L6 POLICY ENGINE",
    subtitle: "Applies workspace rules, thresholds, and policies to decide allow, review, or block.",
    position: position(4.15, 2.2, -0.35),
    labelOffset: [124, -58],
    edgeColor: "#2a1508",
    nodeColor: "#cc4422",
    pulseColor: "#ff6633",
    borderColor: "#ff8833",
    neuronCount: 240,
    firingRate: 0.65,
  },
  {
    id: "injection_firewall",
    label: "L7 INJECTION FIREWALL",
    subtitle: "Filters prompt injection and hostile input through a progressive multi-stage defense.",
    position: position(0.0, -4.2, -0.46),
    labelOffset: [0, 102],
    edgeColor: "#1a1208",
    nodeColor: "#bb7733",
    pulseColor: "#dd9944",
    borderColor: "#ffb155",
    neuronCount: 120,
    firingRate: 0.85,
  },
  {
    id: "telemetry",
    label: "L8 TELEMETRY",
    subtitle: "Captures traces, audit evidence, and exports for dashboards, reviews, and operators.",
    position: position(2.85, -3.5, 0.74),
    labelOffset: [162, 122],
    edgeColor: "#081822",
    nodeColor: "#2288cc",
    pulseColor: "#44bbff",
    borderColor: "#44ccff",
    neuronCount: 220,
    firingRate: 0.7,
  },
];

const ACTIVE_CLUSTERS: Record<AIState, string[]> = {
  idle: [],
  listening: ["session_graph", "taint_tracking", "nhi_identity", "adaptive_risk"],
  thinking: ["session_graph", "adaptive_risk", "policy_engine", "sandbox", "telemetry"],
  speaking: ["telemetry", "policy_engine", "nhi_identity"],
  executing: ["policy_engine", "sandbox", "injection_firewall", "taint_tracking"],
};

const SUPPORT_CLUSTERS: Record<AIState, string[]> = {
  idle: CLUSTERS.map((cluster) => cluster.id),
  listening: ["policy_engine", "sandbox", "telemetry", "injection_firewall"],
  thinking: ["taint_tracking", "nhi_identity", "sandbox", "injection_firewall"],
  speaking: ["session_graph", "adaptive_risk", "policy_engine", "taint_tracking"],
  executing: ["session_graph", "adaptive_risk", "nhi_identity", "telemetry"],
};

export function getClusterActivity(
  clusterId: string,
  aiState: AIState,
  focusedCluster: string | null = null,
): number {
  if (focusedCluster === clusterId) {
    return 1;
  }

  if (ACTIVE_CLUSTERS[aiState].includes(clusterId)) {
    return aiState === "idle" ? 0.34 : 0.96;
  }

  if (SUPPORT_CLUSTERS[aiState].includes(clusterId)) {
    return aiState === "idle" ? 0.34 : 0.58;
  }

  if (aiState === "idle") {
    return 0.28;
  }

  return 0.3;
}
