import { useState } from 'react';

import { AlertIcon } from '../graph/icons';
import { useApp } from '../stores/appStore';

export function ErrorScreen() {
  const { error, reset, startDemo } = useApp();
  const [open, setOpen] = useState(false);
  if (!error) return null;
  return (
    <main className="br-analyzing" data-testid="error-screen">
      <div className="br-landing-bg is-dim" aria-hidden />
      <section className="br-analyzing-card br-error-card" role="alert">
        <div className="br-error-icon">
          <AlertIcon size={22} />
        </div>
        <h1 className="br-error-title">{error.title}</h1>
        <p className="br-error-msg">{error.message}</p>
        {(error.detail || error.code) && (
          <>
            <button type="button" className="br-btn br-btn-ghost" onClick={() => setOpen(!open)} aria-expanded={open}>
              {open ? 'Hide technical details' : 'View technical details'}
            </button>
            {open && (
              <pre className="br-error-detail" data-testid="error-detail">
                {`code: ${error.code}\n${error.detail ?? ''}`.trim()}
              </pre>
            )}
          </>
        )}
        <div className="br-error-actions">
          <button type="button" className="br-btn" onClick={reset}>
            Back
          </button>
          <button type="button" className="br-btn br-btn-primary" onClick={() => void startDemo()}>
            Watch demo incident
          </button>
        </div>
      </section>
    </main>
  );
}
