const LABELS = [
  {
    title: "Rete neurale distribuita",
    subtitle: "architettura di attivazioni interconnesse",
    top: "12%",
    left: "8%",
    tone: "lime",
    delay: "0s",
  },
  {
    title: "Pesi sinaptici adattivi",
    subtitle: "modulazione dinamica delle connessioni",
    top: "18%",
    right: "10%",
    tone: "cyan",
    delay: "0.8s",
  },
  {
    title: "Inferenza profonda multilivello",
    subtitle: "estrazione di pattern e segnali latenti",
    top: "64%",
    left: "7%",
    tone: "amber",
    delay: "1.6s",
  },
  {
    title: "Memoria associativa contestuale",
    subtitle: "richiamo distribuito di stati interni",
    top: "72%",
    right: "11%",
    tone: "rose",
    delay: "2.2s",
  },
  {
    title: "Propagazione del segnale neurale",
    subtitle: "flusso continuo tra nodi, layer e attivazioni",
    top: "86%",
    left: "50%",
    tone: "blue",
    delay: "2.8s",
    center: true,
  },
];

export function NeuralCopyOverlay() {
  return (
    <div className="neural-copy-overlay" aria-hidden="true">
      {LABELS.map((label) => (
        <div
          key={label.title}
          className={`neural-copy neural-copy--${label.tone}${label.center ? " neural-copy--center" : ""}`}
          style={{
            top: label.top,
            left: label.left,
            right: label.right,
            animationDelay: label.delay,
          }}
        >
          <div className="neural-copy__title">{label.title}</div>
          <div className="neural-copy__subtitle">{label.subtitle}</div>
        </div>
      ))}
    </div>
  );
}
