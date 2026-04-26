import { useMemo, useRef } from "react";
import { useFrame } from "@react-three/fiber";
import * as THREE from "three";
import { type AIState, useVisualStore } from "../../store/useVisualStore";
import { CLUSTERS, FILAMENT_ORIGIN_RADIUS, getClusterActivity } from "./neuralData";

const PULSE_COUNT = 200;

const NODE_VERTEX_SHADER = `
  attribute float size;
  attribute vec3 color;
  varying vec3 vColor;

  void main() {
    vColor = color;
    vec4 mvPosition = modelViewMatrix * vec4(position, 1.0);
    gl_PointSize = min(size * (28.0 / -mvPosition.z), 12.0);
    gl_Position = projectionMatrix * mvPosition;
  }
`;

const NODE_FRAGMENT_SHADER = `
  uniform float uOpacity;
  varying vec3 vColor;

  void main() {
    vec2 centered = gl_PointCoord - vec2(0.5);
    float distanceFromCenter = dot(centered, centered);
    if (distanceFromCenter > 0.25) discard;
    float alpha = smoothstep(0.25, 0.0, distanceFromCenter);
    vec3 color = vColor * (0.85 + alpha * 0.6);
    gl_FragColor = vec4(color, uOpacity * alpha);
  }
`;

const PULSE_VERTEX_SHADER = `
  attribute float size;
  attribute vec3 color;
  uniform float uSizeScale;
  varying vec3 vColor;

  void main() {
    vColor = color;
    vec4 mvPosition = modelViewMatrix * vec4(position, 1.0);
    gl_PointSize = min(size * uSizeScale * (14.0 / -mvPosition.z), 14.0);
    gl_Position = projectionMatrix * mvPosition;
  }
`;

const PULSE_FRAGMENT_SHADER = `
  uniform float uOpacity;
  varying vec3 vColor;

  void main() {
    vec2 centered = gl_PointCoord - vec2(0.5);
    float distanceFromCenter = dot(centered, centered);
    if (distanceFromCenter > 0.25) discard;
    float alpha = smoothstep(0.25, 0.0, distanceFromCenter);
    vec3 color = vColor * 1.5;
    gl_FragColor = vec4(color, alpha * uOpacity);
  }
`;

interface Route {
  clusterId: string;
  color: THREE.Color;
  points: THREE.Vector3[];
  cumulativeLengths: number[];
  totalLength: number;
}

interface NetworkData {
  nodePositions: Float32Array;
  nodeColors: Float32Array;
  nodeBaseSizes: Float32Array;
  nodeSizes: Float32Array;
  nodeClusterIndices: Uint16Array;
  nodePhases: Float32Array;
  linePositions: Float32Array;
  lineColors: Float32Array;
  pulsePositions: Float32Array;
  pulseColors: Float32Array;
  pulseSizes: Float32Array;
  pulseRouteIndices: Uint16Array;
  pulseProgress: Float32Array;
  pulseSpeed: Float32Array;
  routes: Route[];
}

function createRandom(seed: number) {
  let state = seed;
  return () => {
    state += 0x6d2b79f5;
    let value = Math.imul(state ^ (state >>> 15), 1 | state);
    value ^= value + Math.imul(value ^ (value >>> 7), 61 | value);
    return ((value ^ (value >>> 14)) >>> 0) / 4294967296;
  };
}

function createBasis(direction: THREE.Vector3) {
  const normalized = direction.clone().normalize();
  const reference =
    Math.abs(normalized.y) > 0.82 ? new THREE.Vector3(1, 0, 0) : new THREE.Vector3(0, 1, 0);
  const tangent = new THREE.Vector3().crossVectors(normalized, reference).normalize();
  const bitangent = new THREE.Vector3().crossVectors(normalized, tangent).normalize();
  return { tangent, bitangent };
}

function buildOrganicPath(
  from: THREE.Vector3,
  to: THREE.Vector3,
  segments: number,
  random: () => number,
  spread: number,
) {
  const points = [from.clone()];
  const delta = to.clone().sub(from);
  const distance = delta.length();
  const direction = delta.normalize();
  const { tangent, bitangent } = createBasis(direction);

  for (let segment = 1; segment < segments; segment += 1) {
    const progress = segment / segments;
    const point = from.clone().lerp(to, progress);
    const lateralSpread = Math.sin(progress * Math.PI) * distance * spread;
    point.addScaledVector(tangent, (random() - 0.5) * lateralSpread);
    point.addScaledVector(bitangent, (random() - 0.5) * lateralSpread);
    points.push(point);
  }

  points.push(to.clone());
  const curve = new THREE.CatmullRomCurve3(points, false, "catmullrom", 0.42);
  return curve.getPoints(Math.max(18, segments * 9));
}

function buildBezierAxon(from: THREE.Vector3, to: THREE.Vector3, random: () => number): THREE.Vector3[] {
  const distance = from.distanceTo(to);
  const direction = to.clone().sub(from).normalize();
  const { tangent, bitangent } = createBasis(direction);

  const offset = distance * (0.18 + random() * 0.22);
  const cp1 = from
    .clone()
    .lerp(to, 0.24)
    .addScaledVector(tangent, (random() - 0.5) * offset)
    .addScaledVector(bitangent, (random() - 0.5) * offset * 0.9)
    .addScaledVector(direction, distance * (0.06 + random() * 0.05));
  const cp2 = from
    .clone()
    .lerp(to, 0.76)
    .addScaledVector(tangent, (random() - 0.5) * offset * 0.95)
    .addScaledVector(bitangent, (random() - 0.5) * offset * 0.82)
    .addScaledVector(direction, -distance * (0.04 + random() * 0.04));

  const curve = new THREE.CubicBezierCurve3(from, cp1, cp2, to);
  return curve.getPoints(56);
}

function buildCurvedLink(
  from: THREE.Vector3,
  to: THREE.Vector3,
  random: () => number,
  bendScale: number,
) {
  const delta = to.clone().sub(from);
  const distance = delta.length();
  if (distance < 0.001) {
    return [from.clone(), to.clone()];
  }

  const direction = delta.normalize();
  const { tangent, bitangent } = createBasis(direction);
  const arc = distance * bendScale;
  const cp1 = from
    .clone()
    .lerp(to, 0.32)
    .addScaledVector(tangent, (random() - 0.5) * arc)
    .addScaledVector(bitangent, (random() - 0.5) * arc * 0.9);
  const cp2 = from
    .clone()
    .lerp(to, 0.68)
    .addScaledVector(tangent, (random() - 0.5) * arc * 0.9)
    .addScaledVector(bitangent, (random() - 0.5) * arc * 0.8);

  const curve = new THREE.CubicBezierCurve3(from, cp1, cp2, to);
  return curve.getPoints(Math.max(14, Math.round(distance * 10)));
}

function addPolyline(
  positions: number[],
  colors: number[],
  points: THREE.Vector3[],
  fromColor: THREE.Color,
  toColor: THREE.Color,
) {
  const segmentCount = Math.max(1, points.length - 1);
  for (let index = 0; index < points.length - 1; index += 1) {
    const start = points[index];
    const end = points[index + 1];
    const startColor = fromColor.clone().lerp(toColor, index / segmentCount);
    const endColor = fromColor.clone().lerp(toColor, (index + 1) / segmentCount);
    positions.push(start.x, start.y, start.z, end.x, end.y, end.z);
    colors.push(startColor.r, startColor.g, startColor.b, endColor.r, endColor.g, endColor.b);
  }
}

function createRoute(clusterId: string, color: THREE.Color, points: THREE.Vector3[]): Route {
  const cumulativeLengths = [0];
  let totalLength = 0;
  for (let index = 1; index < points.length; index += 1) {
    totalLength += points[index].distanceTo(points[index - 1]);
    cumulativeLengths.push(totalLength);
  }
  return { clusterId, color, points: points.map((point) => point.clone()), cumulativeLengths, totalLength };
}

function sampleRoute(route: Route, progress: number, target: THREE.Vector3) {
  const distance = route.totalLength * THREE.MathUtils.clamp(progress, 0, 1);
  for (let index = 1; index < route.cumulativeLengths.length; index += 1) {
    if (distance <= route.cumulativeLengths[index]) {
      const startLength = route.cumulativeLengths[index - 1];
      const endLength = route.cumulativeLengths[index];
      const segment =
        endLength === startLength ? 0 : (distance - startLength) / (endLength - startLength);
      return target.copy(route.points[index - 1]).lerp(route.points[index], segment);
    }
  }
  return target.copy(route.points[route.points.length - 1]);
}

function getPulseSpeed(aiState: AIState, audioLevel: number) {
  switch (aiState) {
    case "listening":
      return 0.5 + audioLevel * 1.5;
    case "thinking":
      return 1.5;
    case "speaking":
      return 1.0;
    case "executing":
      return 1.8;
    default:
      return 0.4;
  }
}

function chooseRouteIndex(routes: Route[], aiState: AIState, focusedCluster: string | null) {
  let totalWeight = 0;
  const weights = routes.map((route) => {
    const weight = 0.35 + getClusterActivity(route.clusterId, aiState, focusedCluster) * 1.55;
    totalWeight += weight;
    return weight;
  });

  let cursor = Math.random() * totalWeight;
  for (let index = 0; index < weights.length; index += 1) {
    cursor -= weights[index];
    if (cursor <= 0) {
      return index;
    }
  }
  return 0;
}

function setPulseColor(target: Float32Array, index: number, color: THREE.Color) {
  target[index * 3] = color.r;
  target[index * 3 + 1] = color.g;
  target[index * 3 + 2] = color.b;
}

function buildNetwork(): NetworkData {
  const random = createRandom(17);

  const nodePositions: number[] = [];
  const nodeColors: number[] = [];
  const nodeBaseSizes: number[] = [];
  const nodeClusterIndices: number[] = [];
  const nodePhases: number[] = [];
  const linePositions: number[] = [];
  const lineColors: number[] = [];
  const routes: Route[] = [];
  const clusterPositions = new Map<string, THREE.Vector3>();
  const allNodeRefs: Array<{ idx: number; pos: THREE.Vector3; color: THREE.Color }> = [];

  CLUSTERS.forEach((cluster, clusterIndex) => {
    const center = new THREE.Vector3(...cluster.position);
    const direction = center.clone().normalize();
    const edgeColor = new THREE.Color(cluster.edgeColor);
    const nodeColor = new THREE.Color(cluster.nodeColor);
    const pulseColor = new THREE.Color(cluster.pulseColor);

    clusterPositions.set(cluster.id, center.clone());

    const trunkStart = direction.clone().multiplyScalar(FILAMENT_ORIGIN_RADIUS);
    const trunk = buildBezierAxon(trunkStart, center, random);
    addPolyline(linePositions, lineColors, trunk, edgeColor, nodeColor.clone().multiplyScalar(0.7));
    routes.push(createRoute(cluster.id, pulseColor, trunk));

    const branchAnchors = [center.clone()];
    const branchCount = 3 + Math.floor(random() * 4);

    for (let branchIndex = 0; branchIndex < branchCount; branchIndex += 1) {
      const trunkPoint = trunk[4 + Math.floor(random() * (trunk.length - 5))].clone();
      const { tangent, bitangent } = createBasis(direction);
      const branchDir = direction
        .clone()
        .multiplyScalar(0.62 + random() * 0.38)
        .addScaledVector(tangent, (random() - 0.5) * 1.55)
        .addScaledVector(bitangent, (random() - 0.5) * 1.55)
        .normalize();

      const branchEnd = center.clone().add(branchDir.multiplyScalar(2.6 + random() * 3.6));
      const branch = buildOrganicPath(
        trunkPoint,
        branchEnd,
        5 + Math.floor(random() * 3),
        random,
        0.18,
      );

      addPolyline(
        linePositions,
        lineColors,
        branch,
        edgeColor.clone().lerp(nodeColor, 0.18),
        nodeColor.clone().multiplyScalar(0.85),
      );
      routes.push(createRoute(cluster.id, pulseColor.clone().lerp(nodeColor, 0.2), branch));
      branchAnchors.push(branchEnd);
    }

    const nodeIndices: number[] = [];
    const localPairs = new Set<string>();
    const nodeCount = 60 + Math.floor(random() * 40);

    for (let nodeIndex = 0; nodeIndex < nodeCount; nodeIndex += 1) {
      const anchor = branchAnchors[Math.floor(random() * branchAnchors.length)];
      const { tangent, bitangent } = createBasis(anchor.clone().normalize());
      const spread = 0.55 + random() * 2.45;
      const position = anchor
        .clone()
        .addScaledVector(tangent, (random() - 0.5) * spread)
        .addScaledVector(bitangent, (random() - 0.5) * spread)
        .addScaledVector(direction, (random() - 0.5) * 0.55);

      if (position.length() < 1.8) {
        position.setLength(1.8 + random() * 0.38);
      }

      const color = nodeColor.clone().lerp(pulseColor, 0.1 + random() * 0.2);
      const isEndpoint = nodeIndex < branchAnchors.length && nodeIndex > 0;
      const size = isEndpoint ? 2.8 + random() * 2.0 : 1.4 + random() * 2.0;

      const index = nodePositions.length / 3;
      nodePositions.push(position.x, position.y, position.z);
      nodeColors.push(color.r, color.g, color.b);
      nodeBaseSizes.push(size);
      nodeClusterIndices.push(clusterIndex);
      nodePhases.push(random() * Math.PI * 2);
      nodeIndices.push(index);
      allNodeRefs.push({ idx: index, pos: position.clone(), color: color.clone() });
    }

    for (let sourceListIndex = 0; sourceListIndex < nodeIndices.length; sourceListIndex += 1) {
      const sourceIndex = nodeIndices[sourceListIndex];
      const source = new THREE.Vector3(
        nodePositions[sourceIndex * 3],
        nodePositions[sourceIndex * 3 + 1],
        nodePositions[sourceIndex * 3 + 2],
      );

      const nearest: Array<{ index: number; distance: number }> = [];
      for (let targetListIndex = 0; targetListIndex < nodeIndices.length; targetListIndex += 1) {
        if (targetListIndex === sourceListIndex) {
          continue;
        }

        const targetIndex = nodeIndices[targetListIndex];
        const target = new THREE.Vector3(
          nodePositions[targetIndex * 3],
          nodePositions[targetIndex * 3 + 1],
          nodePositions[targetIndex * 3 + 2],
        );
        const distance = source.distanceTo(target);
        if (distance < 2.75) {
          nearest.push({ index: targetIndex, distance });
        }
      }

      nearest.sort((left, right) => left.distance - right.distance);

      for (let nearestIndex = 0; nearestIndex < Math.min(3, nearest.length); nearestIndex += 1) {
        const targetIndex = nearest[nearestIndex].index;
        const pairKey =
          sourceIndex < targetIndex ? `${sourceIndex}:${targetIndex}` : `${targetIndex}:${sourceIndex}`;
        if (localPairs.has(pairKey)) {
          continue;
        }
        localPairs.add(pairKey);

        const target = new THREE.Vector3(
          nodePositions[targetIndex * 3],
          nodePositions[targetIndex * 3 + 1],
          nodePositions[targetIndex * 3 + 2],
        );
        addPolyline(
          linePositions,
          lineColors,
          buildCurvedLink(source, target, random, 0.28),
          edgeColor.clone().lerp(nodeColor, 0.25),
          edgeColor.clone().lerp(nodeColor, 0.5),
        );
      }

      if (sourceListIndex % 3 === 0) {
        const anchor = branchAnchors[Math.floor(random() * branchAnchors.length)];
        addPolyline(
          linePositions,
          lineColors,
          buildCurvedLink(source, anchor, random, 0.34),
          edgeColor.clone().lerp(nodeColor, 0.18),
          edgeColor.clone().lerp(nodeColor, 0.55),
        );
      }
    }
  });

  for (let fromIndex = 0; fromIndex < CLUSTERS.length; fromIndex += 1) {
    for (let toIndex = fromIndex + 1; toIndex < CLUSTERS.length; toIndex += 1) {
      const fromCluster = CLUSTERS[fromIndex];
      const toCluster = CLUSTERS[toIndex];
      const from = clusterPositions.get(fromCluster.id);
      const to = clusterPositions.get(toCluster.id);
      if (!from || !to) {
        continue;
      }

      const bridge = buildBezierAxon(from, to, random);
      const fromColor = new THREE.Color(fromCluster.edgeColor).lerp(
        new THREE.Color(fromCluster.nodeColor),
        0.25,
      );
      const toColor = new THREE.Color(toCluster.edgeColor).lerp(
        new THREE.Color(toCluster.nodeColor),
        0.25,
      );
      addPolyline(linePositions, lineColors, bridge, fromColor, toColor);
      routes.push(
        createRoute(
          random() > 0.5 ? fromCluster.id : toCluster.id,
          new THREE.Color(random() > 0.5 ? fromCluster.pulseColor : toCluster.pulseColor),
          bridge,
        ),
      );
    }
  }

  const ambientCount = 240;
  for (let index = 0; index < ambientCount; index += 1) {
    const radius = 2.2 + random() * 5.5;
    const theta = random() * Math.PI * 2;
    const phi = Math.acos(1 - random() * 2);
    const position = new THREE.Vector3(
      radius * Math.sin(phi) * Math.cos(theta),
      radius * Math.sin(phi) * Math.sin(theta),
      radius * Math.cos(phi),
    );

    const x = position.x;
    let red: number;
    let green: number;
    let blue: number;

    if (x < -0.5) {
      red = 0.4 + random() * 0.3;
      green = 0.6 + random() * 0.3;
      blue = 0.1 + random() * 0.15;
    } else if (x > 0.5) {
      red = 0.6 + random() * 0.3;
      green = 0.15 + random() * 0.2;
      blue = 0.1 + random() * 0.15;
    } else {
      red = 0.1 + random() * 0.15;
      green = 0.3 + random() * 0.3;
      blue = 0.6 + random() * 0.3;
    }

    const color = new THREE.Color(red, green, blue);
    const ambientIndex = nodePositions.length / 3;
    nodePositions.push(position.x, position.y, position.z);
    nodeColors.push(color.r, color.g, color.b);
    nodeBaseSizes.push(0.8 + random() * 1.2);
    nodeClusterIndices.push(Math.floor(random() * CLUSTERS.length));
    nodePhases.push(random() * Math.PI * 2);
    allNodeRefs.push({ idx: ambientIndex, pos: position.clone(), color: color.clone() });
  }

  const plexusMaxDist = 2.7;
  const plexusMaxConn = 2;
  for (let index = 0; index < allNodeRefs.length; index += 1) {
    const a = allNodeRefs[index];
    if (a.idx < CLUSTERS.length * 60) {
      continue;
    }

    let connections = 0;
    const nearby: Array<{ j: number; distSq: number }> = [];

    for (let otherIndex = 0; otherIndex < allNodeRefs.length && connections < plexusMaxConn; otherIndex += 1) {
      if (otherIndex === index) {
        continue;
      }

      const b = allNodeRefs[otherIndex];
      const dx = a.pos.x - b.pos.x;
      const dy = a.pos.y - b.pos.y;
      const dz = a.pos.z - b.pos.z;
      const distSq = dx * dx + dy * dy + dz * dz;
      if (distSq < plexusMaxDist * plexusMaxDist) {
        nearby.push({ j: otherIndex, distSq });
      }
    }

    nearby.sort((left, right) => left.distSq - right.distSq);
    for (let nearbyIndex = 0; nearbyIndex < Math.min(plexusMaxConn, nearby.length); nearbyIndex += 1) {
      const b = allNodeRefs[nearby[nearbyIndex].j];
      const dimA = a.color.clone().multiplyScalar(0.35);
      const dimB = b.color.clone().multiplyScalar(0.35);
      addPolyline(linePositions, lineColors, buildCurvedLink(a.pos, b.pos, random, 0.2), dimA, dimB);
      connections += 1;
    }
  }

  const pulsePositions = new Float32Array(PULSE_COUNT * 3);
  const pulseColors = new Float32Array(PULSE_COUNT * 3);
  const pulseSizes = new Float32Array(PULSE_COUNT);
  const pulseRouteIndices = new Uint16Array(PULSE_COUNT);
  const pulseProgress = new Float32Array(PULSE_COUNT);
  const pulseSpeed = new Float32Array(PULSE_COUNT);
  const scratch = new THREE.Vector3();

  for (let index = 0; index < PULSE_COUNT; index += 1) {
    const routeIndex = Math.floor(random() * routes.length);
    const progress = random();
    pulseRouteIndices[index] = routeIndex;
    pulseProgress[index] = progress;
    pulseSpeed[index] = 0.8 + random() * 1.5;
    pulseSizes[index] = 3.8 + random() * 2.2;
    sampleRoute(routes[routeIndex], progress, scratch);
    pulsePositions[index * 3] = scratch.x;
    pulsePositions[index * 3 + 1] = scratch.y;
    pulsePositions[index * 3 + 2] = scratch.z;
    setPulseColor(pulseColors, index, routes[routeIndex].color);
  }

  return {
    nodePositions: new Float32Array(nodePositions),
    nodeColors: new Float32Array(nodeColors),
    nodeBaseSizes: new Float32Array(nodeBaseSizes),
    nodeSizes: new Float32Array(nodeBaseSizes),
    nodeClusterIndices: new Uint16Array(nodeClusterIndices),
    nodePhases: new Float32Array(nodePhases),
    linePositions: new Float32Array(linePositions),
    lineColors: new Float32Array(lineColors),
    pulsePositions,
    pulseColors,
    pulseSizes,
    pulseRouteIndices,
    pulseProgress,
    pulseSpeed,
    routes,
  };
}

export function NeuralNetwork() {
  const nodesRef = useRef<THREE.Points>(null);
  const linesRef = useRef<THREE.LineSegments>(null);
  const pulsesRef = useRef<THREE.Points>(null);
  const nodeMaterialRef = useRef<THREE.ShaderMaterial>(null);
  const pulseMaterialRef = useRef<THREE.ShaderMaterial>(null);

  const aiState = useVisualStore((state) => state.aiState);
  const audioLevel = useVisualStore((state) => state.audioLevel);
  const focusedCluster = useVisualStore((state) => state.focusedCluster);
  const selectedCluster = useVisualStore((state) => state.selectedCluster);
  const pulsesState = useVisualStore((state) => state.pulses);
  const prunePulses = useVisualStore((state) => state.prunePulses);
  const data = useMemo(() => buildNetwork(), []);
  const scratch = useMemo(() => new THREE.Vector3(), []);
  const burstEnergyRef = useRef<Float32Array>(new Float32Array(CLUSTERS.length));
  const pruneAccumRef = useRef(0);

  useFrame(({ clock }, delta) => {
    const time = clock.getElapsedTime();
    const activeCluster = selectedCluster ?? focusedCluster;

    const burst = burstEnergyRef.current;
    for (let index = 0; index < burst.length; index += 1) {
      burst[index] = 0;
    }

    const now = performance.now();
    for (const pulse of pulsesState) {
      const age = (now - pulse.createdAt) / 1000;
      if (age > 1.8) {
        continue;
      }
      const decay = Math.exp(-age * 2.4);
      const contribution = pulse.intensity * decay;
      if (pulse.cluster) {
        const clusterIndex = CLUSTERS.findIndex((cluster) => cluster.id === pulse.cluster);
        if (clusterIndex >= 0) {
          burst[clusterIndex] += contribution * 1.8;
        } else {
          for (let index = 0; index < burst.length; index += 1) {
            burst[index] += contribution * 0.6;
          }
        }
      } else {
        for (let index = 0; index < burst.length; index += 1) {
          burst[index] += contribution * 0.9;
        }
      }
    }

    pruneAccumRef.current += delta;
    if (pruneAccumRef.current > 0.4) {
      pruneAccumRef.current = 0;
      prunePulses();
    }

    const maxBurst = Math.max(...burst, 0);
    const activityByCluster = CLUSTERS.map(
      (cluster, index) => getClusterActivity(cluster.id, aiState, activeCluster) + burst[index] * 0.5,
    );
    const pulseSpeed = getPulseSpeed(aiState, audioLevel) * (1 + maxBurst * 0.8);

    if (linesRef.current) {
      const material = linesRef.current.material as THREE.LineBasicMaterial;
      const target =
        aiState === "idle"
          ? 0.38
          : aiState === "thinking"
            ? 0.52
            : aiState === "executing"
              ? 0.55
              : 0.45;
      material.opacity = THREE.MathUtils.lerp(material.opacity, target, 0.08);
    }

    if (nodeMaterialRef.current) {
      const target =
        0.78 +
        (aiState === "thinking" ? 0.08 : 0) +
        (aiState === "listening" ? audioLevel * 0.12 : 0) +
        maxBurst * 0.18;
      nodeMaterialRef.current.uniforms.uOpacity.value = THREE.MathUtils.lerp(
        nodeMaterialRef.current.uniforms.uOpacity.value as number,
        target,
        0.12,
      );
    }

    if (nodesRef.current) {
      const sizeAttr = nodesRef.current.geometry.getAttribute("size") as THREE.BufferAttribute;
      const sizes = sizeAttr.array as Float32Array;
      for (let index = 0; index < sizes.length; index += 1) {
        const clusterIndex = data.nodeClusterIndices[index];
        const activity = activityByCluster[clusterIndex];
        const cluster = CLUSTERS[clusterIndex];
        const firing = cluster ? cluster.firingRate : 0.5;
        const burstGain = burst[clusterIndex];
        const flickerRate = firing * 2.5 + burstGain * 6;
        const flickerAmp = 0.12 * firing + burstGain * 0.9;
        const twinkle = 1 + Math.sin(time * flickerRate + data.nodePhases[index]) * flickerAmp;
        const spike =
          burstGain > 0.2 &&
          Math.sin(time * 18 + data.nodePhases[index] * 7) > 1 - burstGain
            ? 1.9
            : 1.0;
        sizes[index] = data.nodeBaseSizes[index] * twinkle * spike * (0.92 + activity * 0.65);
      }
      sizeAttr.needsUpdate = true;
    }

    if (pulseMaterialRef.current) {
      const opacityUniform = pulseMaterialRef.current.uniforms.uOpacity;
      const sizeUniform = pulseMaterialRef.current.uniforms.uSizeScale;
      opacityUniform.value = THREE.MathUtils.lerp(
        opacityUniform.value as number,
        0.82 +
          (aiState === "thinking" ? 0.1 : 0) +
          (aiState === "executing" ? 0.12 : 0) +
          maxBurst * 0.25,
        0.1,
      );
      sizeUniform.value = THREE.MathUtils.lerp(
        sizeUniform.value as number,
        (aiState === "idle" ? 1.0 : aiState === "executing" ? 1.15 : 1.08) + maxBurst * 0.6,
        0.12,
      );
    }

    if (pulsesRef.current) {
      const posAttr = pulsesRef.current.geometry.getAttribute("position") as THREE.BufferAttribute;
      const colAttr = pulsesRef.current.geometry.getAttribute("color") as THREE.BufferAttribute;
      const positions = posAttr.array as Float32Array;
      const colors = colAttr.array as Float32Array;
      let colorsChanged = false;

      for (let index = 0; index < PULSE_COUNT; index += 1) {
        const routeIndex = data.pulseRouteIndices[index];
        const route = data.routes[routeIndex];
        const progressDelta =
          (delta * pulseSpeed * data.pulseSpeed[index]) / Math.max(route.totalLength, 0.001);
        let progress = data.pulseProgress[index] + progressDelta;
        let nextRouteIndex = routeIndex;

        if (progress >= 1) {
          progress %= 1;
          nextRouteIndex = chooseRouteIndex(data.routes, aiState, activeCluster);
          data.pulseRouteIndices[index] = nextRouteIndex;
          setPulseColor(colors, index, data.routes[nextRouteIndex].color);
          colorsChanged = true;
        }

        data.pulseProgress[index] = progress;
        sampleRoute(data.routes[nextRouteIndex], progress, scratch);
        positions[index * 3] = scratch.x;
        positions[index * 3 + 1] = scratch.y;
        positions[index * 3 + 2] = scratch.z;
      }

      posAttr.needsUpdate = true;
      if (colorsChanged) {
        colAttr.needsUpdate = true;
      }
    }
  });

  return (
    <group>
      <lineSegments ref={linesRef}>
        <bufferGeometry>
          <bufferAttribute
            attach="attributes-position"
            count={data.linePositions.length / 3}
            array={data.linePositions}
            itemSize={3}
          />
          <bufferAttribute
            attach="attributes-color"
            count={data.lineColors.length / 3}
            array={data.lineColors}
            itemSize={3}
          />
        </bufferGeometry>
        <lineBasicMaterial
          vertexColors
          transparent
          opacity={0.42}
          depthWrite={false}
          blending={THREE.AdditiveBlending}
        />
      </lineSegments>

      <points ref={nodesRef}>
        <bufferGeometry>
          <bufferAttribute
            attach="attributes-position"
            count={data.nodePositions.length / 3}
            array={data.nodePositions}
            itemSize={3}
          />
          <bufferAttribute
            attach="attributes-color"
            count={data.nodeColors.length / 3}
            array={data.nodeColors}
            itemSize={3}
          />
          <bufferAttribute attach="attributes-size" count={data.nodeSizes.length} array={data.nodeSizes} itemSize={1} />
        </bufferGeometry>
        <shaderMaterial
          ref={nodeMaterialRef}
          uniforms={{ uOpacity: { value: 0.78 } }}
          vertexShader={NODE_VERTEX_SHADER}
          fragmentShader={NODE_FRAGMENT_SHADER}
          transparent
          depthWrite={false}
          blending={THREE.AdditiveBlending}
        />
      </points>

      <points ref={pulsesRef}>
        <bufferGeometry>
          <bufferAttribute
            attach="attributes-position"
            count={data.pulsePositions.length / 3}
            array={data.pulsePositions}
            itemSize={3}
          />
          <bufferAttribute
            attach="attributes-color"
            count={data.pulseColors.length / 3}
            array={data.pulseColors}
            itemSize={3}
          />
          <bufferAttribute attach="attributes-size" count={data.pulseSizes.length} array={data.pulseSizes} itemSize={1} />
        </bufferGeometry>
        <shaderMaterial
          ref={pulseMaterialRef}
          uniforms={{ uOpacity: { value: 0.88 }, uSizeScale: { value: 1 } }}
          vertexShader={PULSE_VERTEX_SHADER}
          fragmentShader={PULSE_FRAGMENT_SHADER}
          transparent
          depthWrite={false}
          blending={THREE.AdditiveBlending}
        />
      </points>
    </group>
  );
}
