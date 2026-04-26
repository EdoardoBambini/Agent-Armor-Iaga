import { type CSSProperties, type RefObject, useEffect, useRef } from "react";
import * as THREE from "three";
import { useVisualStore } from "../../store/useVisualStore";
import { CLUSTERS, getClusterActivity } from "./neuralData";
import "./ClusterLabelOverlay.css";

interface Props {
  containerRef: RefObject<HTMLDivElement>;
  camera: THREE.Camera | null;
}

export function ClusterLabelOverlay({ containerRef, camera }: Props) {
  const aiState = useVisualStore((state) => state.aiState);
  const focusedCluster = useVisualStore((state) => state.focusedCluster);
  const selectedCluster = useVisualStore((state) => state.selectedCluster);
  const setSelectedCluster = useVisualStore((state) => state.setSelectedCluster);
  const activeCluster = selectedCluster ?? focusedCluster;
  const labelRefs = useRef<Record<string, HTMLDivElement | null>>({});
  const lineRefs = useRef<Record<string, SVGLineElement | null>>({});

  useEffect(() => {
    if (!camera) {
      return;
    }

    let frame = 0;
    const projected = new THREE.Vector3();

    const update = () => {
      const container = containerRef.current;
      if (!container) {
        frame = requestAnimationFrame(update);
        return;
      }

      const bounds = container.getBoundingClientRect();
      if (bounds.width === 0 || bounds.height === 0) {
        frame = requestAnimationFrame(update);
        return;
      }

      for (const cluster of CLUSTERS) {
        const label = labelRefs.current[cluster.id];
        const line = lineRefs.current[cluster.id];
        if (!label) {
          continue;
        }

        projected.set(...cluster.position).project(camera);
        const visible =
          projected.z > -1 &&
          projected.z < 1 &&
          Math.abs(projected.x) < 1.2 &&
          Math.abs(projected.y) < 1.2;

        if (!visible) {
          label.style.opacity = "0";
          if (line) {
            line.style.opacity = "0";
          }
          continue;
        }

        const activity = getClusterActivity(cluster.id, aiState, activeCluster);
        const isSelected = selectedCluster === cluster.id;
        const cx = (projected.x * 0.5 + 0.5) * bounds.width;
        const cy = (-projected.y * 0.5 + 0.5) * bounds.height;
        const fromCenterX = cx - bounds.width * 0.5;
        const fromCenterY = cy - bounds.height * 0.5;
        const radialLength = Math.hypot(fromCenterX, fromCenterY) || 1;
        const radialPush = 28 + activity * 12;
        const lx = cx + cluster.labelOffset[0] + (fromCenterX / radialLength) * radialPush;
        const ly = cy + cluster.labelOffset[1] + (fromCenterY / radialLength) * radialPush;
        const scale = 0.94 + activity * 0.1 + (isSelected ? 0.08 : 0);

        label.style.opacity = `${isSelected ? 1 : 0.34 + activity * 0.22}`;
        label.style.transform = `translate3d(${lx}px, ${ly}px, 0) translate(-50%, -50%) scale(${scale})`;

        if (line) {
          line.setAttribute("x1", String(cx));
          line.setAttribute("y1", String(cy));
          line.setAttribute("x2", String(lx));
          line.setAttribute("y2", String(ly));
          line.style.opacity = `${isSelected ? 0.72 : 0.08 + activity * 0.1}`;
        }
      }

      frame = requestAnimationFrame(update);
    };

    update();
    return () => cancelAnimationFrame(frame);
  }, [activeCluster, aiState, camera, containerRef, selectedCluster]);

  return (
    <div className="cluster-label-overlay" aria-hidden="true">
      <svg className="cluster-label-svg">
        {CLUSTERS.map((cluster) => (
          <line
            key={cluster.id}
            ref={(element) => {
              lineRefs.current[cluster.id] = element;
            }}
            className="cluster-label-line"
            stroke={cluster.borderColor}
          />
        ))}
      </svg>
      {CLUSTERS.map((cluster) => (
        <div
          key={cluster.id}
          ref={(element) => {
            labelRefs.current[cluster.id] = element;
          }}
          className={`cluster-label${activeCluster === cluster.id ? " cluster-label--focused" : ""}${selectedCluster === cluster.id ? " cluster-label--selected" : ""}`}
          style={{ "--border-color": cluster.borderColor, "--label-color": cluster.nodeColor } as CSSProperties}
          onClick={() => {
            setSelectedCluster(selectedCluster === cluster.id ? null : cluster.id);
          }}
        >
          <div className="cluster-label__title">{cluster.label}</div>
          <div className="cluster-label__sub">{cluster.subtitle}</div>
        </div>
      ))}
    </div>
  );
}
