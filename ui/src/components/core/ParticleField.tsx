import { useMemo, useRef } from "react";
import { useFrame } from "@react-three/fiber";
import * as THREE from "three";

const PARTICLE_COUNT = 650;

const VERTEX_SHADER = `
  attribute float size;
  attribute vec3 color;
  attribute float phase;
  attribute float speed;
  attribute float radius;
  uniform float uTime;
  varying vec3 vColor;
  varying float vAlpha;

  void main() {
    vColor = color;
    float r = radius;
    float theta = phase + uTime * speed * 0.06;
    float phi = phase * 2.0 + uTime * speed * 0.025;

    vec3 pos = position;
    pos.x += sin(theta) * r * 0.01;
    pos.y += cos(theta * 0.7) * r * 0.008;
    pos.z += sin(phi) * r * 0.01;

    vec4 mvPosition = modelViewMatrix * vec4(pos, 1.0);
    float dist = -mvPosition.z;
    gl_PointSize = min(size * (16.0 / dist), 2.8);
    gl_Position = projectionMatrix * mvPosition;
    vAlpha = smoothstep(32.0, 8.0, dist) * 0.35;
  }
`;

const FRAGMENT_SHADER = `
  varying vec3 vColor;
  varying float vAlpha;

  void main() {
    vec2 centered = gl_PointCoord - vec2(0.5);
    float distanceFromCenter = dot(centered, centered);
    if (distanceFromCenter > 0.25) discard;
    float alpha = smoothstep(0.25, 0.02, distanceFromCenter) * vAlpha;
    gl_FragColor = vec4(vColor * 1.08, alpha);
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

const COLOR_PALETTE = [
  [0.04, 0.07, 0.12],
  [0.05, 0.09, 0.18],
  [0.06, 0.12, 0.2],
  [0.08, 0.07, 0.16],
  [0.04, 0.12, 0.14],
  [0.09, 0.08, 0.14],
];

export function ParticleField() {
  const fieldRef = useRef<THREE.Points>(null);
  const materialRef = useRef<THREE.ShaderMaterial>(null);

  const data = useMemo(() => {
    const random = createRandom(91);
    const positions = new Float32Array(PARTICLE_COUNT * 3);
    const colors = new Float32Array(PARTICLE_COUNT * 3);
    const sizes = new Float32Array(PARTICLE_COUNT);
    const phases = new Float32Array(PARTICLE_COUNT);
    const speeds = new Float32Array(PARTICLE_COUNT);
    const radii = new Float32Array(PARTICLE_COUNT);

    for (let index = 0; index < PARTICLE_COUNT; index += 1) {
      const radius = 6.5 + random() * 18;
      const theta = random() * Math.PI * 2;
      const phi = Math.acos(1 - random() * 2);

      positions[index * 3] = radius * Math.sin(phi) * Math.cos(theta);
      positions[index * 3 + 1] = radius * Math.sin(phi) * Math.sin(theta);
      positions[index * 3 + 2] = radius * Math.cos(phi);

      const palette = COLOR_PALETTE[Math.floor(random() * COLOR_PALETTE.length)];
      const brightness = 0.45 + random() * 0.4;
      colors[index * 3] = palette[0] * brightness;
      colors[index * 3 + 1] = palette[1] * brightness;
      colors[index * 3 + 2] = palette[2] * brightness;

      sizes[index] = 0.9 + random() * 1.6;
      phases[index] = random() * Math.PI * 2;
      speeds[index] = 0.3 + random() * 2.0;
      radii[index] = radius;
    }

    return { positions, colors, sizes, phases, speeds, radii };
  }, []);

  useFrame(({ clock }) => {
    if (!fieldRef.current) {
      return;
    }

    const time = clock.getElapsedTime();
    fieldRef.current.rotation.y = time * 0.006;
    fieldRef.current.rotation.x = Math.sin(time * 0.05) * 0.03;
    if (materialRef.current) {
      materialRef.current.uniforms.uTime.value = time;
    }
  });

  return (
    <points ref={fieldRef}>
      <bufferGeometry>
        <bufferAttribute attach="attributes-position" count={PARTICLE_COUNT} array={data.positions} itemSize={3} />
        <bufferAttribute attach="attributes-color" count={PARTICLE_COUNT} array={data.colors} itemSize={3} />
        <bufferAttribute attach="attributes-size" count={PARTICLE_COUNT} array={data.sizes} itemSize={1} />
        <bufferAttribute attach="attributes-phase" count={PARTICLE_COUNT} array={data.phases} itemSize={1} />
        <bufferAttribute attach="attributes-speed" count={PARTICLE_COUNT} array={data.speeds} itemSize={1} />
        <bufferAttribute attach="attributes-radius" count={PARTICLE_COUNT} array={data.radii} itemSize={1} />
      </bufferGeometry>
      <shaderMaterial
        ref={materialRef}
        uniforms={{ uTime: { value: 0 } }}
        vertexShader={VERTEX_SHADER}
        fragmentShader={FRAGMENT_SHADER}
        transparent
        depthWrite={false}
        blending={THREE.NormalBlending}
      />
    </points>
  );
}
