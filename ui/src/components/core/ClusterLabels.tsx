import { useRef } from "react";
import { useFrame } from "@react-three/fiber";
import * as THREE from "three";
import { useVisualStore } from "../../store/useVisualStore";
import { CLUSTERS, getClusterActivity } from "./neuralData";

export function ClusterLabels() {
  const groupRef = useRef<THREE.Group>(null);
  const aiState = useVisualStore((state) => state.aiState);
  const focusedCluster = useVisualStore((state) => state.focusedCluster);
  const selectedCluster = useVisualStore((state) => state.selectedCluster);
  const activeCluster = selectedCluster ?? focusedCluster;

  useFrame(({ clock }) => {
    const group = groupRef.current;
    if (!group) {
      return;
    }

    const time = clock.getElapsedTime();

    for (let index = 0; index < group.children.length; index += 1) {
      const mesh = group.children[index] as THREE.Mesh;
      const cluster = CLUSTERS[index];
      if (!cluster) {
        continue;
      }

      const material = mesh.material as THREE.MeshStandardMaterial;
      const activity = getClusterActivity(cluster.id, aiState, activeCluster);
      const pulse = 1 + Math.sin(time * 1.5 + index * 0.5) * 0.1 * activity;

      mesh.scale.setScalar(1.0 + activity * 0.6 + pulse * 0.08);
      material.opacity = 0.35 + activity * 0.6;
      material.emissiveIntensity = 0.5 + activity * 1.5;
    }
  });

  return (
    <group ref={groupRef}>
      {CLUSTERS.map((cluster) => (
        <mesh key={cluster.id} position={cluster.position}>
          <sphereGeometry args={[0.08, 16, 16]} />
          <meshStandardMaterial
            color={cluster.nodeColor}
            emissive={cluster.pulseColor}
            emissiveIntensity={0.8}
            roughness={0.2}
            metalness={0.1}
            transparent
            opacity={0.6}
            depthWrite={false}
          />
        </mesh>
      ))}
    </group>
  );
}
