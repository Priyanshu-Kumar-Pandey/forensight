import { useEffect, useState } from "react";
import { fetchTimeline } from "../api";
import { useInvestigation } from "../state/InvestigationContext";
import type { TimelineEvent } from "../types";

export default function TimelinePage() {
  const { investigation } = useInvestigation();
  const [events, setEvents] = useState<TimelineEvent[]>([]);

  useEffect(() => {
    if (investigation) fetchTimeline(investigation.id).then(setEvents);
  }, [investigation]);

  if (!investigation) return <p className="muted">Select an investigation first.</p>;

  return (
    <div>
      <h1>Investigation Timeline</h1>
      <p className="muted small">
        Chronologically reconstructed events. Flags mark suspicious sequences (e.g. download→execute).
      </p>
      <div className="timeline">
        {events.map((ev) => (
          <div className="tli" key={ev.id}>
            <div className="tdot" data-risk={ev.risk_level.toLowerCase()} />
            <div className="tcontent">
              <div className="ttime">{new Date(ev.timestamp).toLocaleString()}</div>
              <div className="tdesc">{ev.description}</div>
              <div className="tmeta">
                <span className={`risk ${ev.risk_level.toLowerCase()}`}>{ev.risk_level}</span>
                {ev.flags.map((f) => (
                  <span key={f} className="flag">
                    ⚑ {f.replace(/_/g, " ")}
                  </span>
                ))}
              </div>
            </div>
          </div>
        ))}
      </div>
      {events.length === 0 && <p className="muted">No timeline events. Run analysis first.</p>}
    </div>
  );
}
