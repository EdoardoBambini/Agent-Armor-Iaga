import { useRef } from "react";
import { useFrame } from "@react-three/fiber";
import * as THREE from "three";
import { useVisualStore } from "../../store/useVisualStore";

interface RingProps {
  radius: number;
  tilt: [number, number, number];
  speed: number;
  color: string;
  tube: number;
}

function Ring({ radius, tilt, speed, color, tube }: RingProps) {
  const ref = useRef<THREE.Mesh>(null);
  const aiState = useVisualStore((state) => state.aiState);

  useFrame(({ clock }) => {
    if (!ref.current) {
      return;
    }

    const time = clock.getElapsedTime();
    ref.current.rotation.x = tilt[0] + time * speed * 0.3;
    ref.current.rotation.y = tilt[1] + time * speed;
    ref.current.rotation.z = tilt[2] + time * speed * 0.2;
    const energy = aiState === "idle" ? 0.3 : 0.65;
    (ref.current.material as THREE.MeshBasicMaterial).opacity =
      0.028 + Math.sin(time * 0.5 + radius) * 0.012 + energy * 0.018;
  });

  return (
    <mesh ref={ref}>
      <torusGeometry args={[radius, tube, 24, 220]} />
      <meshBasicMaterial
        color={color}
        transparent
        opacity={0.04}
        blending={THREE.AdditiveBlending}
        depthWrite={false}
      />
    </mesh>
  );
}

export function EnergyRings() {
  return (
    <group>
      <Ring radius={1.02} tilt={[0.3, 0, 0.1]} speed={0.12} color="#00bbff" tube={0.009} />
      <Ring radius={1.34} tilt={[-0.45, 0.75, 0.18]} speed={-0.08} color="#55b6ff" tube={0.007} />
      <Ring radius={1.68} tilt={[0.72, -0.24, 0.4]} speed={0.06} color="#4f7fff" tube={0.006} />
    </group>
  );
}
