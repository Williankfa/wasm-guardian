import React, { useState, useRef } from 'react';
import './App.css';
import {
  OPCODES, parseSections, extractStrings,
  analisarOpcodes, gerarDiagnostico, STRING_FILTERS,
  decompileFunction, readULEB128, T, tagFunctions, TAG_PRIORITY,
  parseImports, buildCallGraph, runTaintAnalysis,
  calcularEntropia, extrairStringsOpcodes,
} from './utils.js';

export default function App() {
  const [status,         setStatus]         = useState({ type:'idle', message:'' });
  const [wasmDetails,    setWasmDetails]     = useState(null);
  const [sections,       setSections]       = useState([]);
  const [strings,        setStrings]        = useState([]);
  const [opcodes,        setOpcodes]        = useState(null);
  const [diagnostico,    setDiagnostico]    = useState(null);
  const [filtro,         setFiltro]         = useState('todos');
  const [dragOver,       setDragOver]       = useState(false);
  const [lang,           setLang]           = useState('en');
  const [selectedFunc,   setSelectedFunc]   = useState(null);
  const [pseudocode,     setPseudocode]     = useState('');
  const [funcTags,       setFuncTags]       = useState([]);
  const [taintFlows,     setTaintFlows]     = useState([]);
  const [entropia,       setEntropia]       = useState(null);
  const [stringsOpcodes, setStringsOpcodes] = useState([]);

  const inputRef  = useRef(null);
  const bufferRef = useRef(null);

  const t = T[lang];

  const FILTROS = [
    { id:'todos',  label: t.filtAll   },
    { id:'urls',   label: t.filtUrls  },
    { id:'chaves', label: t.filtKeys  },
    { id:'flags',  label: t.filtFlags },
  ];

  function processBuffer(buffer, fileName, fileSize) {
    if (buffer.length < 8) {
      setStatus({ type:'error', message: t.statusSmall });
      return;
    }
    const magic   = Array.from(buffer.slice(0,4)).map(b => b.toString(16).padStart(2,'0')).join(' ');
    const version = Array.from(buffer.slice(4,8)).map(b => b.toString(16).padStart(2,'0')).join(' ');

    if (magic !== '00 61 73 6d') {
      setStatus({ type:'error', message: t.statusInvalid });
      setWasmDetails(null); setSections([]); setStrings([]);
      setOpcodes(null); setDiagnostico(null); setPseudocode(''); setFuncTags([]);
      setTaintFlows([]); setEntropia(null); setStringsOpcodes([]);
      return;
    }

    bufferRef.current = buffer;

    // Entropia de Shannon e reconstrução dinâmica de strings
    const ent = calcularEntropia(buffer);
    setEntropia(ent);
    setStringsOpcodes(extrairStringsOpcodes(buffer));

    const parsed = parseSections(buffer);
    const code   = parsed.find(s => s.id === 10);
    const op     = code ? analisarOpcodes(buffer, code) : null;
    const tags   = code ? tagFunctions(buffer, code)    : [];

    setSections(parsed);
    setStrings(extractStrings(buffer));
    setOpcodes(op);
    setDiagnostico(op ? gerarDiagnostico(op) : null);
    setFuncTags(tags);

    // Análise estática de fluxo de dados (Taint Analysis)
    const importList  = parseImports(buffer, parsed);
    const importCount = importList.length;
    const graph       = code ? buildCallGraph(buffer, code, importCount) : {};
    const flows       = runTaintAnalysis(importList, graph, tags);
    setTaintFlows(flows);

    setSelectedFunc(null);
    setPseudocode('');
    setStatus({ type:'success', message: t.statusOk(parsed.length) });
    setWasmDetails({
      name:       fileName,
      size:       `${(fileSize / 1024).toFixed(2)} KB`,
      magicHex:   magic.toUpperCase(),
      versionDec: version === '01 00 00 00' ? '1' : '?',
      versionHex: version.toUpperCase(),
    });
  }

  function handleFile(file) {
    if (!file) return;
    setStatus({ type:'processing', message:`Loading ${file.name}...` });
    const reader = new FileReader();
    reader.onload = (e) => processBuffer(new Uint8Array(e.target.result), file.name, file.size);
    reader.readAsArrayBuffer(file);
  }

  function handleInputChange(e) { handleFile(e.target.files[0]); }
  function handleDrop(e)        { e.preventDefault(); setDragOver(false); handleFile(e.dataTransfer.files[0]); }
  function handleDragOver(e)    { e.preventDefault(); setDragOver(true); }
  function handleDragLeave()    { setDragOver(false); }

  function handleDecompile() {
    if (selectedFunc === null || !bufferRef.current) return;
    const codeSection = sections.find(s => s.id === 10);
    if (!codeSection) return;
    try {
      let off = codeSection.offset;
      const { bytesRead: lb } = readULEB128(bufferRef.current, off);
      off += lb;
      for (let f = 0; f <= selectedFunc; f++) {
        const { value: sz, bytesRead: sb } = readULEB128(bufferRef.current, off);
        off += sb;
        if (f === selectedFunc) {
          setPseudocode(decompileFunction(bufferRef.current, off, sz));
          return;
        }
        off += sz;
      }
    } catch (e) { setPseudocode(`;; Error: ${e.message}`); }
  }

  function handleCopy() {
      if (!pseudocode) return;
      navigator.clipboard.writeText(pseudocode).catch(() => {});
    }

    function handleExportMarkdown() {
      const lines = [];
      const ts = new Date().toISOString();

      lines.push(`# WASM Guardian — Security Report`);
      lines.push(`> Generated: ${ts}\n`);

      // 1. Metadata
      lines.push(`## 1. File Metadata`);
      if (wasmDetails) {
        lines.push(`| Field | Value |`);
        lines.push(`|---|---|`);
        lines.push(`| Name | ${wasmDetails.name} |`);
        lines.push(`| Size | ${wasmDetails.size} |`);
        lines.push(`| Magic Bytes | \`${wasmDetails.magicHex}\` |`);
        lines.push(`| Version | v${wasmDetails.versionDec} (${wasmDetails.versionHex}) |`);
      } else {
        lines.push(`_No file loaded._`);
      }
      lines.push(``);

      // 2. Risk Diagnosis
      lines.push(`## 2. Risk Diagnosis`);
      if (entropia) {
        const entropyFlag = entropia.obfuscated ? '⚠️ HIGH — possible obfuscation/compression' : '✅ Normal';
        lines.push(`- **Shannon Entropy:** ${entropia.value} / 8.0 — ${entropyFlag}`);
      }
      if (opcodes) {
        const total = (opcodes.fluxo + opcodes.memoria + opcodes.matematica) || 1;
        lines.push(`- **Control Flow opcodes:** ${opcodes.fluxo} (${((opcodes.fluxo/total)*100).toFixed(1)}%)`);
        lines.push(`- **Memory opcodes:** ${opcodes.memoria} (${((opcodes.memoria/total)*100).toFixed(1)}%)`);
        lines.push(`- **Math opcodes:** ${opcodes.matematica} (${((opcodes.matematica/total)*100).toFixed(1)}%)`);
      }
      if (diagnostico) {
        const levelMap = { ok: '✅ OK', aviso: '⚠️ WARNING', perigo: '🚨 DANGER' };
        lines.push(`- **Behavioral Level:** ${levelMap[diagnostico.nivel] ?? diagnostico.nivel}`);
      }
      lines.push(``);

      // 3. Taint Analysis — Suspicious Flows
      lines.push(`## 3. Taint Analysis — Suspicious Flows`);
      if (taintFlows.length > 0) {
        taintFlows.forEach((path, i) => {
          lines.push(`${i + 1}. \`${path.join(' → ')}\``);
        });
      } else {
        lines.push(`_No suspicious flows detected._`);
      }
      lines.push(``);

      // 4. Extracted Strings — Threat Intelligence
      lines.push(`## 4. Extracted Strings — Threat Intelligence`);
      const threats = strings.filter(s => /https?:|key|secret|token|password|flag\{/i.test(s));
      if (threats.length > 0) {
        lines.push(`### 🚨 High-Risk Strings (${threats.length})`);
        threats.forEach(s => lines.push(`- \`${s}\``));
        lines.push(``);
      }
      const urls = strings.filter(s => /https?:\/\//i.test(s));
      if (urls.length > 0) {
        lines.push(`### 🔗 URLs (${urls.length})`);
        urls.forEach(s => lines.push(`- ${s}`));
        lines.push(``);
      }
      lines.push(`_Total strings extracted: ${strings.length}_`);
      lines.push(``);

      // 5. Auditor Notes (blank)
      lines.push(`## 5. Auditor Notes`);
      lines.push(``);
      lines.push(`> _Add your manual observations here._`);
      lines.push(``);

      const blob = new Blob([lines.join('\n')], { type: 'text/markdown' });
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement('a');
      a.href     = url;
      a.download = `wasm-report-${wasmDetails?.name ?? 'unknown'}.md`;
      a.click();
      URL.revokeObjectURL(url);
    }

  function handleDownload() {
    if (!pseudocode) return;
    const name = `function_${selectedFunc}`;
    const text = `${name}\n${'='.repeat(40)}\n${pseudocode}`;
    const blob = new Blob([text], { type: 'text/plain' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = `${name}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  }

  const sortedFuncs    = [...funcTags].sort((a, b) => TAG_PRIORITY[a.tag] - TAG_PRIORITY[b.tag]);
  const selectedTag    = funcTags.find(f => f.index === selectedFunc)?.tag ?? null;
  const visibleStrings = strings.filter(STRING_FILTERS[filtro]);
  const total = opcodes ? (opcodes.fluxo + opcodes.memoria + opcodes.matematica) || 1 : 1;

  return (
    <div className="app">

      <header className="app-header">
        <span className="logo-icon">&#9039;</span>
        <span className="logo-text">WASM Guardian</span>
        <span className="logo-version">v2.0</span>
        <span className="header-sub">Static Security Analyzer</span>
        <div className="lang-toggle">
          <button className={`lang-btn${lang === 'en' ? ' active' : ''}`} onClick={() => setLang('en')}>EN</button>
          <button className={`lang-btn${lang === 'pt' ? ' active' : ''}`} onClick={() => setLang('pt')}>PT</button>
        </div>
      </header>

      <main className="app-main">

        {/* Drop Zone */}
        <div
          className={`drop-zone${dragOver ? ' drag-over' : ''}`}
          onDrop={handleDrop}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onClick={() => inputRef.current?.click()}
        >
          <input ref={inputRef} type="file" accept=".wasm" onChange={handleInputChange} onClick={e => e.stopPropagation()} />
          <span className="drop-zone-icon">&#x2B21;</span>
          <p className="drop-zone-label">{t.dropLabel}</p>
          <p className="drop-zone-sub">{t.dropSub}</p>
        </div>

        {/* Status */}
        <div className={`status-bar ${status.type}`}>
          <span className="status-dot" />
          {status.message || t.statusIdle}
        </div>

        {/* Metadata */}
        {wasmDetails && (
          <div className="card">
            <p className="card-title">{t.metaTitle}</p>
            <div className="meta-grid">
              <div className="meta-cell">
                <span className="meta-label">{t.metaName}</span>
                <span className="meta-value">{wasmDetails.name}</span>
              </div>
              <div className="meta-cell">
                <span className="meta-label">{t.metaSize}</span>
                <span className="meta-value cyan">{wasmDetails.size}</span>
              </div>
              <div className="meta-cell">
                <span className="meta-label">{t.metaMagic}</span>
                <span className="meta-value yellow">{wasmDetails.magicHex}</span>
              </div>
              <div className="meta-cell">
                <span className="meta-label">{t.metaVer}</span>
                <span className="meta-value">v{wasmDetails.versionDec} ({wasmDetails.versionHex})</span>
              </div>
            </div>
            <div style={{ marginTop: '16px', display: 'flex', justifyContent: 'flex-end' }}>
              <button
                onClick={handleExportMarkdown}
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: '11px',
                  fontWeight: '700',
                  letterSpacing: '0.06em',
                  padding: '7px 18px',
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid rgba(251,146,60,0.6)',
                  background: 'rgba(251,146,60,0.08)',
                  color: '#fb923c',
                  cursor: 'pointer',
                  transition: 'var(--transition)',
                }}
                onMouseEnter={e => e.currentTarget.style.background = 'rgba(251,146,60,0.16)'}
                onMouseLeave={e => e.currentTarget.style.background = 'rgba(251,146,60,0.08)'}
              >
                ↓ Export Markdown
              </button>
            </div>
          </div>
        )}

        {/* Shannon Entropy */}
        {entropia && (
          <div className={`status-bar ${entropia.obfuscated ? 'error' : 'success'}`}>
            <span className="status-dot" />
            {t.entropyTitle}: {entropia.value} / 8.0
            {entropia.obfuscated && ` -- ${t.entropyHigh}`}
          </div>
        )}

        {/* Sections */}
        {sections.length > 0 && (
          <div className="card">
            <p className="card-title">{t.sectTitle}</p>
            <table className="sections-table">
              <thead>
                <tr>
                  <th>{t.sectName}</th>
                  <th>{t.sectId}</th>
                  <th>{t.sectOffset}</th>
                  <th>{t.sectBytes}</th>
                </tr>
              </thead>
              <tbody>
                {sections.map((s, i) => (
                  <tr key={i}>
                    <td className={`section-name${s.id === 0 ? ' custom' : ''}`}>{s.name}</td>
                    <td>0x{s.id.toString(16).toUpperCase().padStart(2,'0')}</td>
                    <td>0x{s.offset.toString(16).toUpperCase()}</td>
                    <td>{s.size}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Opcodes */}
        {opcodes && (
          <div className="card">
            <p className="card-title">{t.opTitle}</p>
            <div className="opcodes-grid">
              {Object.entries(OPCODES).map(([cat, { color }]) => {
                const labelMap = { fluxo: t.opFlow, memoria: t.opMem, matematica: t.opMath };
                return (
                  <div className="opcode-card" key={cat} style={{ '--card-color': color }}>
                    <div className="opcode-count">{opcodes[cat]}</div>
                    <div className="opcode-label">{labelMap[cat]}</div>
                    <div className="opcode-pct">{((opcodes[cat] / total) * 100).toFixed(1)}%</div>
                  </div>
                );
              })}
            </div>
            {diagnostico && (
              <div className={`diagnostic ${diagnostico.nivel}`}>
                <span className="diagnostic-icon">
                  {diagnostico.nivel === 'perigo' ? '[!]' : diagnostico.nivel === 'aviso' ? '[~]' : '[ok]'}
                </span>
                {diagnostico.nivel === 'perigo' ? t.diagPerigo
                  : diagnostico.nivel === 'aviso' ? t.diagAviso
                  : t.diagOk}
              </div>
            )}
          </div>
        )}

        {/* Strings */}
        {strings.length > 0 && (
          <div className="card">
            <p className="card-title">{t.strTitle}</p>
            <div className="filter-tabs">
              {FILTROS.map(f => (
                <button
                  key={f.id}
                  className={`filter-btn${filtro === f.id ? ' active' : ''}`}
                  onClick={() => setFiltro(f.id)}
                >
                  {f.label}
                </button>
              ))}
              <span className="filter-count">{visibleStrings.length} / {strings.length}</span>
            </div>
            <div className="strings-list">
              {visibleStrings.length === 0
                ? <p className="strings-empty">{t.strEmpty}</p>
                : visibleStrings.map((s, i) => (
                  <span
                    key={i}
                    className={`string-item${/https?:|key|secret|token|password|flag\{/i.test(s) ? ' threat' : ''}`}
                  >
                    {s}
                  </span>
                ))
              }
            </div>
          </div>
        )}

        {/* Dynamic String Reconstruction */}
        {stringsOpcodes && (
          <div className="card">
            <p className="card-title">{t.dynStrTitle || "Dynamic String Reconstruction"}</p>
            <div className="strings-list">
              {stringsOpcodes.length === 0 ? (
                <p className="empty-text" style={{ color: '#666', fontSize: '14px', margin: 0 }}>
                  Nenhuma string dinâmica oculta (via opcodes) foi detectada neste binário.
                </p>
              ) : (
                stringsOpcodes.map((s, i) => (
                  <span key={i} className="string-item threat">{s}</span>
                ))
              )}
            </div>
          </div>
        )}


        {/* Taint Analysis -- Suspicious Flows */}
        {taintFlows.length > 0 && (
          <div className="card">
            <p className="card-title">Taint Analysis -- Suspicious Flows</p>
            <div className="strings-list">
              {taintFlows.map((path, i) => (
                <span key={i} className="string-item threat">
                  {path.join(' -> ')}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Decompiler */}
        {sortedFuncs.length > 0 && (
          <div className="card">
            <p className="card-title">{t.decompTitle}</p>
            <div className="decomp-controls">
              <select
                className="decomp-select"
                value={selectedFunc ?? ''}
                onChange={e => { setSelectedFunc(Number(e.target.value)); setPseudocode(''); }}
              >
                <option value="" disabled>{t.decompSelect}</option>
                {sortedFuncs.map(({ index, tag }) => (
                  <option key={index} value={index}>
                    [{t.tagLabels[tag]}] function_{index}
                  </option>
                ))}
              </select>
              {selectedTag && (
                <span className={`fn-tag fn-tag--${selectedTag.toLowerCase()}`}>
                  {t.tagLabels[selectedTag]}
                </span>
              )}
              <button className="decomp-btn" onClick={handleDecompile}>
                {t.decompBtn}
              </button>
            </div>
            {pseudocode && (
              <>
                <div className="pseudocode-actions">
                  <button className="action-btn action-btn--copy"     onClick={handleCopy}>{t.copyBtn}</button>
                  <button className="action-btn action-btn--download" onClick={handleDownload}>{t.downloadBtn}</button>
                </div>
                <pre className="pseudocode">{pseudocode}</pre>
              </>
            )}
          </div>
        )}

      </main>

      <footer className="app-footer">
        <span><span className="footer-dot" />{t.footerOnline}</span>
        <span>{t.footerSub}</span>
        <span>{t.footerLocal}</span>
      </footer>

    </div>
  );
}