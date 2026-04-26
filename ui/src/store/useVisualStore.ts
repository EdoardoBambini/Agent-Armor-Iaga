import { create } from "zustand";

export type AIState = "idle" | "listening" | "thinking" | "speaking" | "executing";
export type NeuronPulseKind = "observe" | "analyze" | "govern" | "report";

export interface NeuronPulse {
  id: number;
  kind: NeuronPulseKind;
  intensity: number;
  createdAt: number;
  cluster?: string;
}

interface VisualStore {
  aiState: AIState;
  setAIState: (state: AIState) => void;
  focusedCluster: string | null;
  setFocusedCluster: (cluster: string | null) => void;
  selectedCluster: string | null;
  setSelectedCluster: (cluster: string | null) => void;
  audioLevel: number;
  setAudioLevel: (level: number) => void;
  pulses: NeuronPulse[];
  firePulse: (kind: NeuronPulseKind, intensity?: number, cluster?: string) => void;
  prunePulses: () => void;
}

let pulseIdCounter = 0;

export const useVisualStore = create<VisualStore>((set) => ({
  aiState: "idle",
  setAIState: (aiState) => set({ aiState }),

  focusedCluster: null,
  setFocusedCluster: (focusedCluster) => set({ focusedCluster }),

  selectedCluster: null,
  setSelectedCluster: (selectedCluster) => set({ selectedCluster }),

  audioLevel: 0,
  setAudioLevel: (audioLevel) => set({ audioLevel }),

  pulses: [],
  firePulse: (kind, intensity = 1, cluster) =>
    set((state) => ({
      pulses: [
        ...state.pulses.slice(-64),
        {
          id: ++pulseIdCounter,
          kind,
          intensity: Math.max(0, Math.min(1, intensity)),
          createdAt: performance.now(),
          cluster,
        },
      ],
    })),
  prunePulses: () =>
    set((state) => {
      const now = performance.now();
      const kept = state.pulses.filter((pulse) => now - pulse.createdAt < 1800);
      return kept.length === state.pulses.length ? state : { pulses: kept };
    }),
}));
