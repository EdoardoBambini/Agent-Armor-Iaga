import { useMemo, useRef } from "react";
import { useFrame } from "@react-three/fiber";
import * as THREE from "three";

const NEBULA_COUNT = 620;

const LOBE_CENTERS = [
  [0.22, -0.05, 0.03],
  [-0.18, 0.12, -0.04],
  [0.08, 0.18, 0.22],
] as const;

const VERTEX_SHADER = `
  attribute float size;
  attribute vec3 color;
  attribute float phase;
  attribute float radius;
  attribute float drift;
  uniform float uTime;
  varying vec3 vColor;
  varying float vAlpha;

  void main() {
    vColor = color;
    float p = phase + uTime * (0.014 + drift * 0.011);
    vec3 pos = position;
    float swirl = 0.032 + radius * 0.05;
    pos.x += sin(p * 1.22) * swirl;
    pos.y += cos(p * 0.86) * swirl * 0.72;
    pos.z += sin(p * 1.48) * swirl * 0.84;

    vec4 mv = modelViewMatrix * vec4(pos, 1.0);
    float dist = -mv.z;
    gl_PointSize = min(size * (42.0 / dist), 32.0);
    gl_Position = projectionMatrix * mv;
    float radialFade = 1.0 - smoothstep(0.32, 2.4, radius);
    vAlpha = smoothstep(14.0, 1.8, dist) * (0.04 + radialFade * 0.145);
  }
`;

const FRAGMENT_SHADER = `
  varying vec3 vColor;
  varying float vAlpha;

  void main() {
    vec2 centered = gl_PointCoord - vec2(0.5);
    float distanceFromCenter = dot(centered, centered) * 4.0;
    float haze = exp(-distanceFromCenter * 1.22);
    float core = exp(-distanceFromCenter * 4.1);
    float alpha = (haze * 0.84 + core * 0.2) * vAlpha;
    if (alpha < 0.006) discard;
    gl_FragColor = vec4(vColor * (0.98 + core * 0.08), alpha);
  }
`;

function createRandom(seed: number) {
  let state = seed;
  return () => {
    state += 0x6d2b79f5;
    let value = Math.imul(state ^ (state >>> 15), 1 | state);
    value ^= value + Math.imul(value ^ (value >>> 7), 61 | value);
    return ((value ^ (value >>> 14)) >>> 0) / 4294967296;
  };
}

const NEBULA_COLORS = [
  [0.05, 0.13, 0.32],
  [0.06, 0.16, 0.36],
  [0.08, 0.19, 0.4],
  [0.05, 0.15, 0.3],
  [0.09, 0.2, 0.44],
  [0.12, 0.2, 0.34],
];

export function NebulaField() {
  const ref = useRef<THREE.Points>(null);
  const materialRef = useRef<THREE.ShaderMaterial>(null);

  const data = useMemo(() => {
    const random = createRandom(42);
    const positions = new Float32Array(NEBULA_COUNT * 3);
    const colors = new Float32Array(NEBULA_COUNT * 3);
    const sizes = new Float32Array(NEBULA_COUNT);
    const phases = new Float32Array(NEBULA_COUNT);
    const radii = new Float32Array(NEBULA_COUNT);
    const drifts = new Float32Array(NEBULA_COUNT);

    for (let index = 0; index < NEBULA_COUNT; index += 1) {
      const radius = 0.06 + Math.pow(random(), 2.45) * 1.95;
      const theta = random() * Math.PI * 2;
      const phi = Math.acos(1 - random() * 2);
      const lobe = LOBE_CENTERS[Math.floor(random() * LOBE_CENTERS.length)];
      const lobePull = 0.1 + random() * 0.42;

      positions[index * 3] = lobe[0] * lobePull + radius * Math.sin(phi) * Math.cos(theta) * 1.16;
      positions[index * 3 + 1] = lobe[1] * lobePull + radius * Math.sin(phi) * Math.sin(theta) * 0.84;
      positions[index * 3 + 2] = lobe[2] * lobePull + radius * Math.cos(phi) * 0.98;

      const color = NEBULA_COLORS[Math.floor(random() * NEBULA_COLORS.length)];
      const brightness = 0.42 + random() * 0.28;
      colors[index * 3] = color[0] * brightness;
      colors[index * 3 + 1] = color[1] * brightness;
      colors[index * 3 + 2] = color[2] * brightness;

      sizes[index] = 8 + (1 - radius / 2.2) * 13 + random() * 8;
      phases[index] = random() * Math.PI * 2;
      radii[index] = radius + lobePull * 0.2;
      drifts[index] = 0.18 + random() * 0.62;
    }

    return { positions, colors, sizes, phases, radii, drifts };
  }, []);

  useFrame(({ clock }) => {
    if (!ref.current) {
      return;
    }

    const time = clock.getElapsedTime();
    ref.current.rotation.y = time * 0.016;
    ref.current.rotation.x = Math.cos(time * 0.11) * 0.04;
    ref.current.rotation.z = Math.sin(time * 0.13) * 0.05;
    ref.current.scale.set(
      0.96 + Math.sin(time * 0.18) * 0.06,
      0.8 + Math.cos(time * 0.16 + 0.8) * 0.05,
      0.88 + Math.sin(time * 0.14 + 1.7) * 0.06,
    );

    if (materialRef.current) {
      materialRef.current.uniforms.uTime.value = time;
    }
  });

  return (
    <points ref={ref}>
      <bufferGeometry>
        <bufferAttribute attach="attributes-position" count={NEBULA_COUNT} array={data.positions} itemSize={3} />
        <bufferAttribute attach="attributes-color" count={NEBULA_COUNT} array={data.colors} itemSize={3} />
        <bufferAttribute attach="attributes-size" count={NEBULA_COUNT} array={data.sizes} itemSize={1} />
        <bufferAttribute attach="attributes-phase" count={NEBULA_COUNT} array={data.phases} itemSize={1} />
        <bufferAttribute attach="attributes-radius" count={NEBULA_COUNT} array={data.radii} itemSize={1} />
        <bufferAttribute attach="attributes-drift" count={NEBULA_COUNT} array={data.drifts} itemSize={1} />
      </bufferGeometry>
      <shaderMaterial
        ref={materialRef}
        uniforms={{ uTime: { value: 0 } }}
        vertexShader={VERTEX_SHADER}
        fragmentShader={FRAGMENT_SHADER}
        transparent
        depthWrite={false}
        blending={THREE.AdditiveBlending}
      />
    </points>
  );
}
