import { NeuralScene } from "./components/core/NeuralScene";
import { useAgentArmorDemo } from "./hooks/useAgentArmorDemo";

export function App() {
  useAgentArmorDemo();

  return <NeuralScene />;
}
