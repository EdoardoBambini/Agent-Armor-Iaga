import { useMemo, useRef } from "react";
import { useFrame } from "@react-three/fiber";
import * as THREE from "three";
import { useVisualStore } from "../../store/useVisualStore";

const CORE_COUNT = 980;
const RING_COUNT = 720;
const PLUME_COUNT = 560;
const SPARK_COUNT = 132;

const VERTEX_SHADER = `
  attribute float size;
  attribute vec3 color;
  attribute float phase;
  attribute float drift;
  attribute float orbit;
  uniform float uTime;
  uniform float uAlpha;
  varying vec3 vColor;
  varying float vAlpha;

  void main() {
    vColor = color;

    float t = uTime * (0.2 + drift * 0.16) + phase;
    vec3 pos = position;

    float radial = length(pos.xy) + 0.0001;
    vec2 normal2 = pos.xy / radial;
    vec2 tangent = vec2(-normal2.y, normal2.x);
    float halo = smoothstep(0.18, 0.82, radial);

    pos.xy += tangent * sin(t + orbit) * (0.018 + orbit * 0.028);
    pos.xy += normal2 * cos(t * 0.84 + orbit * 1.7) * (0.012 + halo * 0.02);
    pos.z += sin(t * 1.15 + orbit) * (0.02 + drift * 0.028);
    pos.x += sin(t * 0.72 + phase * 1.6) * 0.01;
    pos.y += cos(t * 0.68 + phase * 0.9) * 0.012;

    vec4 mvPosition = modelViewMatrix * vec4(pos, 1.0);
    float dist = -mvPosition.z;
    gl_PointSize = min(size * (104.0 / dist), 54.0);
    gl_Position = projectionMatrix * mvPosition;

    float depthFade = smoothstep(26.0, 2.5, dist);
    vAlpha = depthFade * uAlpha * (0.92 + halo * 0.5);
  }
`;

const FRAGMENT_SHADER = `
  varying vec3 vColor;
  varying float vAlpha;

  void main() {
    vec2 centered = gl_PointCoord - vec2(0.5);
    float d = dot(centered, centered) * 4.0;
    float haze = exp(-d * 1.12);
    float core = exp(-d * 4.4);
    float alpha = (haze * 0.82 + core * 0.24) * vAlpha;
    if (alpha < 0.008) discard;
    gl_FragColor = vec4(vColor * (0.94 + core * 0.12), alpha);
  }
`;

interface CloudData {
  positions: Float32Array;
  colors: Float32Array;
  sizes: Float32Array;
  phases: Float32Array;
  drifts: Float32Array;
  orbits: Float32Array;
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

function getStateEnergy(aiState: string) {
  switch (aiState) {
    case "listening":
      return 0.6;
    case "thinking":
      return 0.9;
    case "speaking":
      return 0.72;
    case "executing":
      return 1.0;
    default:
      return 0.42;
  }
}

function createCoreCloud() {
  const random = createRandom(11);
  const positions = new Float32Array(CORE_COUNT * 3);
  const colors = new Float32Array(CORE_COUNT * 3);
  const sizes = new Float32Array(CORE_COUNT);
  const phases = new Float32Array(CORE_COUNT);
  const drifts = new Float32Array(CORE_COUNT);
  const orbits = new Float32Array(CORE_COUNT);
  const lobes = [
    [-0.16, 0.04, 0.02],
    [0.18, -0.04, 0.04],
    [0.02, -0.18, -0.02],
    [0.0, 0.2, 0.06],
  ] as const;
  const palette = [
    [0.09, 0.2, 0.42],
    [0.12, 0.26, 0.52],
    [0.1, 0.3, 0.58],
    [0.14, 0.34, 0.62],
  ] as const;

  for (let index = 0; index < CORE_COUNT; index += 1) {
    const radius = 0.08 + Math.pow(random(), 1.62) * 0.68;
    const theta = random() * Math.PI * 2;
    const phi = Math.acos(1 - random() * 2);
    const lobe = lobes[Math.floor(random() * lobes.length)];
    const lobePull = 0.08 + random() * 0.28;

    positions[index * 3] = lobe[0] * lobePull + radius * Math.sin(phi) * Math.cos(theta) * 1.06;
    positions[index * 3 + 1] = lobe[1] * lobePull + radius * Math.sin(phi) * Math.sin(theta) * 1.26;
    positions[index * 3 + 2] = lobe[2] * lobePull + radius * Math.cos(phi) * 0.72;

    const color = palette[Math.floor(random() * palette.length)];
    const brightness = 0.65 + random() * 0.4;
    colors[index * 3] = color[0] * brightness;
    colors[index * 3 + 1] = color[1] * brightness;
    colors[index * 3 + 2] = color[2] * brightness;

    sizes[index] = 14 + (1 - radius / 0.82) * 12 + random() * 7;
    phases[index] = random() * Math.PI * 2;
    drifts[index] = 0.22 + random() * 0.9;
    orbits[index] = 0.12 + random() * 0.48;
  }

  return { positions, colors, sizes, phases, drifts, orbits };
}

function createRingCloud() {
  const random = createRandom(23);
  const positions = new Float32Array(RING_COUNT * 3);
  const colors = new Float32Array(RING_COUNT * 3);
  const sizes = new Float32Array(RING_COUNT);
  const phases = new Float32Array(RING_COUNT);
  const drifts = new Float32Array(RING_COUNT);
  const orbits = new Float32Array(RING_COUNT);
  const palette = [
    [0.18, 0.44, 0.86],
    [0.24, 0.56, 0.95],
    [0.28, 0.68, 1.0],
    [0.2, 0.48, 0.92],
  ] as const;

  for (let index = 0; index < RING_COUNT; index += 1) {
    const angle = random() * Math.PI * 2;
    const radius = 0.74 + (random() - 0.5) * 0.24;
    const verticalDrift = (random() - 0.5) * 0.48;
    const depth = (random() - 0.5) * 0.24;

    positions[index * 3] = Math.cos(angle) * radius + Math.sin(angle * 2.0) * 0.12;
    positions[index * 3 + 1] = Math.sin(angle) * radius * 0.92 + verticalDrift;
    positions[index * 3 + 2] = depth;

    const color = palette[Math.floor(random() * palette.length)];
    const brightness = 0.7 + random() * 0.35;
    colors[index * 3] = color[0] * brightness;
    colors[index * 3 + 1] = color[1] * brightness;
    colors[index * 3 + 2] = color[2] * brightness;

    sizes[index] = 9 + random() * 8.4;
    phases[index] = random() * Math.PI * 2;
    drifts[index] = 0.25 + random() * 0.85;
    orbits[index] = 0.8 + random() * 1.2;
  }

  return { positions, colors, sizes, phases, drifts, orbits };
}

function createPlumeCloud() {
  const random = createRandom(37);
  const positions = new Float32Array(PLUME_COUNT * 3);
  const colors = new Float32Array(PLUME_COUNT * 3);
  const sizes = new Float32Array(PLUME_COUNT);
  const phases = new Float32Array(PLUME_COUNT);
  const drifts = new Float32Array(PLUME_COUNT);
  const orbits = new Float32Array(PLUME_COUNT);
  const palette = [
    [0.22, 0.54, 0.96],
    [0.28, 0.68, 1.0],
    [0.34, 0.78, 1.0],
  ] as const;

  for (let index = 0; index < PLUME_COUNT; index += 1) {
    const y = (random() - 0.5) * 1.5;
    positions[index * 3] =
      -0.2 + Math.sin(y * 3.2 + random() * 0.8) * 0.16 + (random() - 0.5) * 0.12;
    positions[index * 3 + 1] = y * 0.62;
    positions[index * 3 + 2] = (random() - 0.5) * 0.22;

    const color = palette[Math.floor(random() * palette.length)];
    const brightness = 0.72 + random() * 0.34;
    colors[index * 3] = color[0] * brightness;
    colors[index * 3 + 1] = color[1] * brightness;
    colors[index * 3 + 2] = color[2] * brightness;

    sizes[index] = 11 + random() * 10.5;
    phases[index] = random() * Math.PI * 2;
    drifts[index] = 0.2 + random() * 0.8;
    orbits[index] = 0.6 + random() * 0.9;
  }

  return { positions, colors, sizes, phases, drifts, orbits };
}

function createSparkCloud() {
  const random = createRandom(51);
  const positions = new Float32Array(SPARK_COUNT * 3);
  const colors = new Float32Array(SPARK_COUNT * 3);
  const sizes = new Float32Array(SPARK_COUNT);
  const phases = new Float32Array(SPARK_COUNT);
  const drifts = new Float32Array(SPARK_COUNT);
  const orbits = new Float32Array(SPARK_COUNT);

  for (let index = 0; index < SPARK_COUNT; index += 1) {
    const radius = 0.24 + Math.pow(random(), 1.15) * 0.88;
    const angle = random() * Math.PI * 2;
    const depth = (random() - 0.5) * 0.42;

    positions[index * 3] = Math.cos(angle) * radius;
    positions[index * 3 + 1] = Math.sin(angle) * radius * (0.74 + random() * 0.28);
    positions[index * 3 + 2] = depth;

    const brightness = 0.82 + random() * 0.28;
    colors[index * 3] = 0.7 * brightness;
    colors[index * 3 + 1] = 0.9 * brightness;
    colors[index * 3 + 2] = 1.0 * brightness;

    sizes[index] = 7.2 + random() * 5.4;
    phases[index] = random() * Math.PI * 2;
    drifts[index] = 0.22 + random() * 0.7;
    orbits[index] = 1.0 + random() * 1.0;
  }

  return { positions, colors, sizes, phases, drifts, orbits };
}

function createGlowTexture(stops: Array<{ offset: number; color: string }>) {
  const size = 256;
  const canvas = document.createElement("canvas");
  canvas.width = size;
  canvas.height = size;
  const context = canvas.getContext("2d");
  if (!context) {
    return null;
  }

  const gradient = context.createRadialGradient(size / 2, size / 2, 0, size / 2, size / 2, size / 2);
  for (const stop of stops) {
    gradient.addColorStop(stop.offset, stop.color);
  }

  context.clearRect(0, 0, size, size);
  context.fillStyle = gradient;
  context.fillRect(0, 0, size, size);

  const texture = new THREE.CanvasTexture(canvas);
  texture.needsUpdate = true;
  texture.generateMipmaps = false;
  texture.minFilter = THREE.LinearFilter;
  texture.magFilter = THREE.LinearFilter;
  return texture;
}

export function NeuralSphere() {
  const groupRef = useRef<THREE.Group>(null);
  const innerRef = useRef<THREE.Mesh>(null);
  const glowOuterRef = useRef<THREE.Sprite>(null);
  const glowInnerRef = useRef<THREE.Sprite>(null);
  const coreRef = useRef<THREE.Points>(null);
  const ringRef = useRef<THREE.Points>(null);
  const plumeRef = useRef<THREE.Points>(null);
  const sparkRef = useRef<THREE.Points>(null);

  const coreMatRef = useRef<THREE.ShaderMaterial>(null);
  const ringMatRef = useRef<THREE.ShaderMaterial>(null);
  const plumeMatRef = useRef<THREE.ShaderMaterial>(null);
  const sparkMatRef = useRef<THREE.ShaderMaterial>(null);

  const aiState = useVisualStore((state) => state.aiState);
  const audioLevel = useVisualStore((state) => state.audioLevel);

  const coreData = useMemo<CloudData>(() => createCoreCloud(), []);
  const ringData = useMemo<CloudData>(() => createRingCloud(), []);
  const plumeData = useMemo<CloudData>(() => createPlumeCloud(), []);
  const sparkData = useMemo<CloudData>(() => createSparkCloud(), []);
  const outerGlowTexture = useMemo(
    () =>
      createGlowTexture([
        { offset: 0, color: "rgba(180, 235, 255, 0.95)" },
        { offset: 0.18, color: "rgba(110, 190, 255, 0.62)" },
        { offset: 0.46, color: "rgba(52, 118, 255, 0.24)" },
        { offset: 1, color: "rgba(0, 0, 0, 0)" },
      ]),
    [],
  );
  const innerGlowTexture = useMemo(
    () =>
      createGlowTexture([
        { offset: 0, color: "rgba(240, 250, 255, 1)" },
        { offset: 0.14, color: "rgba(158, 226, 255, 0.9)" },
        { offset: 0.4, color: "rgba(54, 158, 255, 0.36)" },
        { offset: 1, color: "rgba(0, 0, 0, 0)" },
      ]),
    [],
  );

  useFrame(({ clock }) => {
    const time = clock.getElapsedTime();
    const energy = getStateEnergy(aiState);
    const audioBoost = aiState === "listening" ? audioLevel * 0.45 : 0;

    if (groupRef.current) {
      groupRef.current.rotation.y = time * 0.05;
      groupRef.current.rotation.x = Math.sin(time * 0.12) * 0.05;
      groupRef.current.rotation.z = Math.cos(time * 0.09) * 0.025;
      groupRef.current.scale.setScalar(
        1.38 + energy * 0.12 + audioBoost * 0.1 + Math.sin(time * 0.22) * 0.035,
      );
    }

    if (innerRef.current) {
      innerRef.current.scale.setScalar(
        1 + Math.sin(time * 1.7) * 0.06 + energy * 0.06 + audioBoost * 0.06,
      );
      (innerRef.current.material as THREE.MeshBasicMaterial).opacity = 0.64 + energy * 0.18;
    }

    if (glowOuterRef.current) {
      glowOuterRef.current.scale.set(
        3.8 + energy * 0.55 + audioBoost * 0.24 + Math.sin(time * 0.28) * 0.1,
        3.3 + energy * 0.45 + Math.cos(time * 0.23 + 0.7) * 0.09,
        1,
      );
      const material = glowOuterRef.current.material as THREE.SpriteMaterial;
      material.opacity = 0.14 + energy * 0.045 + audioBoost * 0.025;
    }

    if (glowInnerRef.current) {
      glowInnerRef.current.scale.set(
        2.2 + energy * 0.26 + audioBoost * 0.12 + Math.cos(time * 0.34) * 0.08,
        2.35 + energy * 0.28 + Math.sin(time * 0.29 + 0.4) * 0.07,
        1,
      );
      const material = glowInnerRef.current.material as THREE.SpriteMaterial;
      material.opacity = 0.19 + energy * 0.06 + audioBoost * 0.035;
    }

    if (coreRef.current) {
      coreRef.current.rotation.z = Math.sin(time * 0.17) * 0.08;
      coreRef.current.scale.set(
        1.2 + energy * 0.12 + Math.sin(time * 0.32) * 0.06,
        1.08 + energy * 0.12 + Math.cos(time * 0.28 + 1.1) * 0.07,
        1.16 + Math.sin(time * 0.24 + 1.9) * 0.06,
      );
    }

    if (ringRef.current) {
      ringRef.current.rotation.z = time * 0.12;
      ringRef.current.rotation.x = Math.sin(time * 0.18) * 0.1;
      ringRef.current.scale.set(
        1.34 + energy * 0.14,
        1.2 + Math.sin(time * 0.26 + 0.7) * 0.1,
        1.26 + Math.cos(time * 0.22 + 1.3) * 0.08,
      );
    }

    if (plumeRef.current) {
      plumeRef.current.rotation.y = -time * 0.08;
      plumeRef.current.rotation.z = Math.sin(time * 0.16 + 0.4) * 0.12;
      plumeRef.current.scale.set(
        1.28 + energy * 0.14,
        1.46 + energy * 0.2 + Math.sin(time * 0.22 + 1.0) * 0.1,
        1.22 + Math.cos(time * 0.2 + 1.8) * 0.08,
      );
    }

    if (sparkRef.current) {
      sparkRef.current.rotation.z = -time * 0.18;
      sparkRef.current.rotation.y = Math.sin(time * 0.12) * 0.08;
      sparkRef.current.scale.setScalar(1 + energy * 0.08 + Math.sin(time * 0.34) * 0.04);
    }

    if (coreMatRef.current) {
      coreMatRef.current.uniforms.uTime.value = time;
      coreMatRef.current.uniforms.uAlpha.value = 0.38 + energy * 0.16 + audioBoost * 0.12;
    }

    if (ringMatRef.current) {
      ringMatRef.current.uniforms.uTime.value = time;
      ringMatRef.current.uniforms.uAlpha.value = 0.18 + energy * 0.08;
    }

    if (plumeMatRef.current) {
      plumeMatRef.current.uniforms.uTime.value = time;
      plumeMatRef.current.uniforms.uAlpha.value = 0.26 + energy * 0.1 + audioBoost * 0.07;
    }

    if (sparkMatRef.current) {
      sparkMatRef.current.uniforms.uTime.value = time;
      sparkMatRef.current.uniforms.uAlpha.value = 0.24 + energy * 0.08;
    }
  });

  return (
    <group ref={groupRef} renderOrder={20}>
      {outerGlowTexture && (
        <sprite ref={glowOuterRef} renderOrder={20}>
          <spriteMaterial
            map={outerGlowTexture}
            color="#4f96ff"
            transparent
            opacity={0.15}
            depthWrite={false}
            depthTest={false}
            blending={THREE.AdditiveBlending}
          />
        </sprite>
      )}

      {innerGlowTexture && (
        <sprite ref={glowInnerRef} renderOrder={21}>
          <spriteMaterial
            map={innerGlowTexture}
            color="#9be1ff"
            transparent
            opacity={0.2}
            depthWrite={false}
            depthTest={false}
            blending={THREE.AdditiveBlending}
          />
        </sprite>
      )}

      <mesh ref={innerRef} renderOrder={21}>
        <sphereGeometry args={[0.09, 20, 20]} />
        <meshBasicMaterial
          color="#eaf8ff"
          transparent
          opacity={0.7}
          blending={THREE.AdditiveBlending}
          depthWrite={false}
          depthTest={false}
        />
      </mesh>

      <points ref={coreRef} renderOrder={22} frustumCulled={false}>
        <bufferGeometry>
          <bufferAttribute attach="attributes-position" count={CORE_COUNT} array={coreData.positions} itemSize={3} />
          <bufferAttribute attach="attributes-color" count={CORE_COUNT} array={coreData.colors} itemSize={3} />
          <bufferAttribute attach="attributes-size" count={CORE_COUNT} array={coreData.sizes} itemSize={1} />
          <bufferAttribute attach="attributes-phase" count={CORE_COUNT} array={coreData.phases} itemSize={1} />
          <bufferAttribute attach="attributes-drift" count={CORE_COUNT} array={coreData.drifts} itemSize={1} />
          <bufferAttribute attach="attributes-orbit" count={CORE_COUNT} array={coreData.orbits} itemSize={1} />
        </bufferGeometry>
        <shaderMaterial
          ref={coreMatRef}
          uniforms={{ uTime: { value: 0 }, uAlpha: { value: 0.38 } }}
          vertexShader={VERTEX_SHADER}
          fragmentShader={FRAGMENT_SHADER}
          transparent
          depthWrite={false}
          depthTest={false}
          blending={THREE.NormalBlending}
        />
      </points>

      <points ref={plumeRef} renderOrder={23} frustumCulled={false}>
        <bufferGeometry>
          <bufferAttribute attach="attributes-position" count={PLUME_COUNT} array={plumeData.positions} itemSize={3} />
          <bufferAttribute attach="attributes-color" count={PLUME_COUNT} array={plumeData.colors} itemSize={3} />
          <bufferAttribute attach="attributes-size" count={PLUME_COUNT} array={plumeData.sizes} itemSize={1} />
          <bufferAttribute attach="attributes-phase" count={PLUME_COUNT} array={plumeData.phases} itemSize={1} />
          <bufferAttribute attach="attributes-drift" count={PLUME_COUNT} array={plumeData.drifts} itemSize={1} />
          <bufferAttribute attach="attributes-orbit" count={PLUME_COUNT} array={plumeData.orbits} itemSize={1} />
        </bufferGeometry>
        <shaderMaterial
          ref={plumeMatRef}
          uniforms={{ uTime: { value: 0 }, uAlpha: { value: 0.26 } }}
          vertexShader={VERTEX_SHADER}
          fragmentShader={FRAGMENT_SHADER}
          transparent
          depthWrite={false}
          depthTest={false}
          blending={THREE.NormalBlending}
        />
      </points>

      <points ref={ringRef} renderOrder={24} frustumCulled={false}>
        <bufferGeometry>
          <bufferAttribute attach="attributes-position" count={RING_COUNT} array={ringData.positions} itemSize={3} />
          <bufferAttribute attach="attributes-color" count={RING_COUNT} array={ringData.colors} itemSize={3} />
          <bufferAttribute attach="attributes-size" count={RING_COUNT} array={ringData.sizes} itemSize={1} />
          <bufferAttribute attach="attributes-phase" count={RING_COUNT} array={ringData.phases} itemSize={1} />
          <bufferAttribute attach="attributes-drift" count={RING_COUNT} array={ringData.drifts} itemSize={1} />
          <bufferAttribute attach="attributes-orbit" count={RING_COUNT} array={ringData.orbits} itemSize={1} />
        </bufferGeometry>
        <shaderMaterial
          ref={ringMatRef}
          uniforms={{ uTime: { value: 0 }, uAlpha: { value: 0.18 } }}
          vertexShader={VERTEX_SHADER}
          fragmentShader={FRAGMENT_SHADER}
          transparent
          depthWrite={false}
          depthTest={false}
          blending={THREE.AdditiveBlending}
        />
      </points>

      <points ref={sparkRef} renderOrder={25} frustumCulled={false}>
        <bufferGeometry>
          <bufferAttribute attach="attributes-position" count={SPARK_COUNT} array={sparkData.positions} itemSize={3} />
          <bufferAttribute attach="attributes-color" count={SPARK_COUNT} array={sparkData.colors} itemSize={3} />
          <bufferAttribute attach="attributes-size" count={SPARK_COUNT} array={sparkData.sizes} itemSize={1} />
          <bufferAttribute attach="attributes-phase" count={SPARK_COUNT} array={sparkData.phases} itemSize={1} />
          <bufferAttribute attach="attributes-drift" count={SPARK_COUNT} array={sparkData.drifts} itemSize={1} />
          <bufferAttribute attach="attributes-orbit" count={SPARK_COUNT} array={sparkData.orbits} itemSize={1} />
        </bufferGeometry>
        <shaderMaterial
          ref={sparkMatRef}
          uniforms={{ uTime: { value: 0 }, uAlpha: { value: 0.24 } }}
          vertexShader={VERTEX_SHADER}
          fragmentShader={FRAGMENT_SHADER}
          transparent
          depthWrite={false}
          depthTest={false}
          blending={THREE.AdditiveBlending}
        />
      </points>
    </group>
  );
}
