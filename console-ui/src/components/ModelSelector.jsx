import React, { useState, useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useAuth } from '../lib/AuthContext';
import { PROVIDERS, MODELS } from '../lib/models';

export default function ModelSelector() {
  const { provider, model, aisaKey, updateProvider, updateModel, updateAisaKey, user } = useAuth();
  const [keyInput, setKeyInput] = useState('');
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  // Close on outside click
  useEffect(() => {
    const handler = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const currentProvider = PROVIDERS[provider];
  const currentModels = MODELS[provider] || [];
  const currentModel = currentModels.find(m => m.id === model) || currentModels[0];

  return (
    <div className="model-selector" ref={ref}>
      <button className="model-trigger" onClick={() => setOpen(!open)}>
        <span className="model-provider-dot" style={{ background: provider === 'vllm' ? 'var(--low)' : 'var(--accent)' }} />
        <span className="model-label">{currentModel?.name || 'Select model'}</span>
        <span className={`chev ${open ? 'up' : ''}`} style={{ marginLeft: 6 }} />
      </button>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, y: -8, scale: 0.96 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -8, scale: 0.96 }}
            transition={{ duration: 0.15 }}
            className="model-dropdown"
          >
            {/* Provider tabs */}
            <div className="model-tabs">
              {Object.values(PROVIDERS).map(p => (
                <button
                  key={p.id}
                  className={`model-tab ${provider === p.id ? 'active' : ''}`}
                  onClick={() => {
                    updateProvider(p.id);
                    updateModel(MODELS[p.id][0].id);
                  }}
                >
                  <span className="model-provider-dot" style={{ background: p.id === 'vllm' ? 'var(--low)' : 'var(--accent)' }} />
                  {p.name}
                </button>
              ))}
            </div>

            <div className="model-tab-desc">{currentProvider.desc}</div>

            {/* AISA key input */}
            {provider === 'aisa' && (
              <div className="model-key-row" style={{ flexDirection: 'column', alignItems: 'flex-start', gap: 4 }}>
                <input
                  type="password"
                  className="model-key-input"
                  placeholder={aisaKey ? "Using saved AISA key" : "AISA.one API key"}
                  value={keyInput}
                  onChange={e => { setKeyInput(e.target.value); updateAisaKey(e.target.value); }}
                  style={{ width: '100%' }}
                />
                {user && aisaKey && !keyInput && (
                  <span className="small" style={{ color: 'var(--low)', fontSize: 10 }}>🔒 Encrypted & saved</span>
                )}
              </div>
            )}

            {/* Model list */}
            <div className="model-list">
              {currentModels.map(m => (
                <button
                  key={m.id}
                  className={`model-item ${model === m.id ? 'active' : ''}`}
                  onClick={() => { updateModel(m.id); setOpen(false); }}
                >
                  <div className="model-item-name">{m.name}</div>
                  <div className="model-item-desc">{m.desc}</div>
                </button>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
