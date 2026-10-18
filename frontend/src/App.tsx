import { useEffect } from 'react';

import { IncidentView } from './components/IncidentView';
import { useApp } from './stores/appStore';
import { AnalysisProgress } from './upload/AnalysisProgress';
import { ErrorScreen } from './upload/ErrorScreen';
import { Landing } from './upload/Landing';

export default function App() {
  const screen = useApp((s) => s.screen);
  const incident = useApp((s) => s.incident);
  const loadService = useApp((s) => s.loadService);

  useEffect(() => {
    void loadService();
  }, [loadService]);

  if (screen === 'error') return <ErrorScreen />;
  if (screen === 'analyzing') return <AnalysisProgress />;
  if (screen === 'incident' && incident) return <IncidentView incident={incident} />;
  return <Landing />;
}
