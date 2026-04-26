import { Suspense, useRef, useState } from "react";
import { Canvas } from "@react-three/fiber";
import { OrbitControls } from "@react-three/drei";
import { Bloom, EffectComposer } from "@react-three/postprocessing";
import { KernelSize } from "postprocessing";
import * as THREE from "three";
import { ClusterLabelOverlay } from "./ClusterLabelOverlay";
import { ClusterLabels } from "./ClusterLabels";
import { EnergyRings } from "./EnergyRings";
import { NebulaField } from "./NebulaField";
import { NeuralNetwork } from "./NeuralNetwork";
import { NeuralSphere } from "./NeuralSphere";
import { ParticleField } from "./ParticleField";
import { SCENE_BACKGROUND } from "./neuralData";

function SceneContent() {
  return (
    <>
      <color attach="background" args={[SCENE_BACKGROUND]} />
      <fog attach="fog" args={[SCENE_BACKGROUND, 14, 30]} />

      <ambientLight color="#88ffdd" intensity={0.4} />
      <directionalLight color="#7ee8ff" intensity={0.4} position={[4, 6, 6]} />
      <pointLight color="#1166ff" intensity={1.5} distance={14} decay={2} position={[0, 0, 0]} />
      <pointLight color="#4488ff" intensity={0.5} distance={12} decay={2} position={[3, 2, -2]} />
      <pointLight color="#ff4488" intensity={0.25} distance={10} decay={2} position={[-3, -1, 2]} />

      <OrbitControls
        enablePan={false}
        enableZoom
        enableDamping
        dampingFactor={0.06}
        rotateSpeed={0.35}
        zoomSpeed={0.55}
        minDistance={3.2}
        maxDistance={15}
        autoRotate
        autoRotateSpeed={0.25}
      />

      <NebulaField />
      <NeuralSphere />
      <EnergyRings />
      <NeuralNetwork />
      <ParticleField />
      <ClusterLabels />

      <EffectComposer multisampling={0}>
        <Bloom
          intensity={1.18}
          luminanceThreshold={0.24}
          luminanceSmoothing={0.72}
          mipmapBlur
          kernelSize={KernelSize.LARGE}
          radius={0.78}
        />
      </EffectComposer>
    </>
  );
}

export function NeuralScene() {
  const containerRef = useRef<HTMLDivElement>(null);
  const [camera, setCamera] = useState<THREE.Camera | null>(null);

  return (
    <div
      ref={containerRef}
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 0,
        background: SCENE_BACKGROUND,
      }}
    >
      <Canvas
        camera={{ position: [0, 0.25, 6.5], fov: 55, near: 0.1, far: 50 }}
        dpr={[1, 1.5]}
        gl={{
          antialias: true,
          alpha: false,
          powerPreference: "high-performance",
          stencil: false,
          depth: true,
          preserveDrawingBuffer: false,
        }}
        onCreated={({ camera: sceneCamera, gl, scene }) => {
          scene.background = new THREE.Color(SCENE_BACKGROUND);
          gl.setClearColor(SCENE_BACKGROUND, 1);
          setCamera(sceneCamera);
        }}
      >
        <Suspense fallback={null}>
          <SceneContent />
        </Suspense>
      </Canvas>
      <ClusterLabelOverlay containerRef={containerRef} camera={camera} />
    </div>
  );
}
