export const SECTION_NAMES = {
  0:'Custom', 1:'Type', 2:'Import', 3:'Function', 4:'Table',
  5:'Memory', 6:'Global', 7:'Export', 8:'Start', 9:'Element',
  10:'Code', 11:'Data', 12:'DataCount',
};

export const OPCODES = {
  fluxo:      { range:[[0x02,0x04],[0x0C,0x0F]], label:'Fluxo de Controle', color:'var(--accent-purple)' },
  memoria:    { range:[[0x28,0x3E]],             label:'Memoria',           color:'var(--accent-cyan)'   },
  matematica: { range:[[0x6A,0x7E]],             label:'Matematica',        color:'var(--accent-green)'  },
};

export const TAG_PRIORITY = { CRITICAL:0, CRYPTO:1, LOGIC:2, STANDARD:3 };

// ── Funções de Parsing de Baixo Nível ──────────────────────────
export function readULEB128(buf, offset) {
  let result = 0, shift = 0, bytesRead = 0;
  while (offset < buf.length) {
    const byte = buf[offset++];
    bytesRead++;
    result |= (byte & 0x7F) << shift;
    if ((byte & 0x80) === 0) break;
    shift += 7;
  }
  return { value: result, bytesRead };
}

export function parseSections(buffer) {
  const sections = [];
  let offset = 8; // Pula a assinatura mágica e versão do WASM
  while (offset < buffer.length) {
    const id = buffer[offset++];
    const { value: size, bytesRead } = readULEB128(buffer, offset);
    offset += bytesRead;
    sections.push({ id, name: SECTION_NAMES[id] ?? `Unknown(${id})`, size, offset });
    offset += size;
  }
  return sections;
}

export function parseImports(buffer, sections) {
  const sec = sections.find(s => s.id === 2);
  if (!sec) return [];
  const imports = [];
  let i = sec.offset;
  const { value: count, bytesRead: cb } = readULEB128(buffer, i);
  i += cb;
  for (let n = 0; n < count; n++) {
    const { value: modLen, bytesRead: mb } = readULEB128(buffer, i); i += mb;
    const mod = String.fromCharCode(...buffer.slice(i, i + modLen)); i += modLen;
    const { value: nameLen, bytesRead: nb } = readULEB128(buffer, i); i += nb;
    const name = String.fromCharCode(...buffer.slice(i, i + nameLen)); i += nameLen;
    const kind = buffer[i++];
    const { bytesRead: ib } = readULEB128(buffer, i); i += ib;
    if (kind === 0) imports.push({ label: `${mod}.${name}`, funcIndex: n });
  }
  return imports;
}

// ── Análise Comportamental e Heurísticas ──────────────────────
export function extractStrings(buffer, minLen = 4) {
  const results = [];
  let current = '';
  for (let i = 0; i < buffer.length; i++) {
    const b = buffer[i];
    if (b >= 32 && b <= 126) { current += String.fromCharCode(b); }
    else { if (current.length >= minLen) results.push(current); current = ''; }
  }
  if (current.length >= minLen) results.push(current);
  return results;
}

export function analisarOpcodes(buffer, secaoCode) {
  const fim = secaoCode.offset + secaoCode.size;
  const contagem = { fluxo:0, memoria:0, matematica:0 };
  for (let i = secaoCode.offset; i < fim; i++) {
    const b = buffer[i];
    for (const [cat, { range }] of Object.entries(OPCODES)) {
      for (const [min, max] of range) {
        if (b >= min && b <= max) { contagem[cat]++; break; }
      }
    }
  }
  return contagem;
}

export function gerarDiagnostico(op) {
  const total = op.fluxo + op.memoria + op.matematica || 1;
  const pct = { matematica: op.matematica / total, memoria: op.memoria / total };
  if (pct.matematica > 0.40) return { nivel:'perigo', msg:'' };
  if (pct.memoria    > 0.55) return { nivel:'aviso',  msg:'' };
  return { nivel:'ok', msg:'' };
}

export function tagFunctions(buffer, codeSection) {
  const results = [];
  let off = codeSection.offset;
  const { value: count, bytesRead: lb } = readULEB128(buffer, off);
  off += lb;

  for (let f = 0; f < count; f++) {
    const { value: sz, bytesRead: sb } = readULEB128(buffer, off);
    off += sb;
    const end = off + sz;
    let i = off;

    let hasCallIndirect = false;
    let hasUnreachable  = false;
    let hasBrTable      = false;
    let insideLoop      = false;
    let i64XorInLoop    = false;
    let i64AndInLoop    = false;

    try {
      const { value: lc, bytesRead: lcb } = readULEB128(buffer, i);
      i += lcb;
      for (let l = 0; l < lcb; l++) {
        const { bytesRead: cb } = readULEB128(buffer, i); i += cb; i++;
      }
      while (i < end) {
        const b = buffer[i++];
        if (b === 0x00) hasUnreachable  = true;
        if (b === 0x11) hasCallIndirect = true;
        if (b === 0x0E) hasBrTable      = true;
        if (b === 0x03) insideLoop      = true;
        if (b === 0x0B && insideLoop)   insideLoop = false;
        if (insideLoop && b === 0x85)   i64XorInLoop = true;
        if (insideLoop && b === 0x83)   i64AndInLoop = true;
      }
    } catch (_) {}

    let tag = 'STANDARD';
    if (hasCallIndirect || (hasBrTable && hasUnreachable)) tag = 'CRITICAL';
    else if (i64XorInLoop || i64AndInLoop)                 tag = 'CRYPTO';
    else if (insideLoop)                                   tag = 'LOGIC';

    results.push({ index: f, tag });
    off = end;
  }
  return results;
}

// ── Análise de Grafo de Chamadas e Taint (Threat Intel) ───────
export function buildCallGraph(buffer, codeSection, importCount) {
  const graph = {};
  let off = codeSection.offset;
  const { value: count, bytesRead: lb } = readULEB128(buffer, off);
  off += lb;

  for (let f = 0; f < count; f++) {
    const realIndex = f + importCount;
    const { value: sz, bytesRead: sb } = readULEB128(buffer, off);
    off += sb;
    const end = off + sz;
    let i = off;
    graph[realIndex] = [];

    try {
      const { value: lc, bytesRead: lcb } = readULEB128(buffer, i); i += lcb;
      for (let l = 0; l < lc; l++) {
        const { bytesRead: xb } = readULEB128(buffer, i); i += xb; i++;
      }
      while (i < end) {
        const b = buffer[i++];
        if (b === 0x10) {
          const { value: callee, bytesRead: xb } = readULEB128(buffer, i); i += xb;
          if (!graph[realIndex].includes(callee)) graph[realIndex].push(callee);
        } else if (b === 0x11) {
          const { bytesRead: xb } = readULEB128(buffer, i); i += xb;
          const { bytesRead: yb } = readULEB128(buffer, i); i += yb;
        }
      }
    } catch (_) {}
    off = end;
  }
  return graph;
}

export function runTaintAnalysis(imports, callGraph, funcTags) {
  const SINK_TAGS = new Set(['CRITICAL', 'CRYPTO']);
  const sinks = new Set(funcTags.filter(f => SINK_TAGS.has(f.tag)).map(f => f.index));
  const flows = [];

  for (const imp of imports) {
    const src = imp.funcIndex;
    // BFS
    const queue = [[src, [imp.label]]];
    const visited = new Set([src]);
    while (queue.length) {
      const [node, path] = queue.shift();
      for (const callee of (callGraph[node] ?? [])) {
        if (visited.has(callee)) continue;
        visited.add(callee);
        const tag = funcTags.find(f => f.index === callee)?.tag ?? '';
        const newPath = [...path, `f${callee}${tag ? `(${tag})` : ''}`];
        if (sinks.has(callee)) { flows.push(newPath); continue; }
        queue.push([callee, newPath]);
      }
    }
  }
  return flows;
}

export const STRING_FILTERS = {
  todos:  () => true,
  urls:   s => /https?:\/\//i.test(s),
  chaves: s => /key|secret|token|password|api|auth/i.test(s),
  flags:  s => /flag\{|ctf\{|htb\{/i.test(s),
};

// ── Entropia de Shannon ───────────────────────────────────────
export function calcularEntropia(uint8Array) {
  const freq = new Uint32Array(256);
  for (let i = 0; i < uint8Array.length; i++) freq[uint8Array[i]]++;

  const len = uint8Array.length;
  let entropia = 0;
  for (let i = 0; i < 256; i++) {
    if (freq[i] === 0) continue;
    const p = freq[i] / len;
    entropia -= p * Math.log2(p);
  }

  return {
    value:      parseFloat(entropia.toFixed(4)),
    obfuscated: entropia > 7.5,
  };
}

// ── Reconstrução dinâmica de strings via opcodes ──────────────
export function extrairStringsOpcodes(uint8Array) {
  const buf     = uint8Array;
  const results = [];
  let current   = '';

  // percorre o buffer inteiro buscando o padrão 0x41 <leb128> 0x36 <align> <offset>
  for (let i = 0; i < buf.length - 2; i++) {
    if (buf[i] !== 0x41) {
      // flush de sequência acumulada
      if (current.length >= 4) results.push(current);
      current = '';
      continue;
    }

    // lê o operando leb128 do i32.const
    let val = 0, shift = 0, j = i + 1;
    while (j < buf.length) {
      const byte = buf[j++];
      val |= (byte & 0x7F) << shift;
      if ((byte & 0x80) === 0) break;
      shift += 7;
    }

    // verifica se o próximo opcode relevante é i32.store (0x36)
    // pula align e offset (ambos leb128, geralmente 1 byte cada em casos simples)
    if (buf[j] !== 0x36) {
      if (current.length >= 4) results.push(current);
      current = '';
      continue;
    }

    // converte o valor para char ASCII imprimível
    const ch = val & 0xFF; // byte menos significativo
    if (ch >= 32 && ch <= 126) {
      current += String.fromCharCode(ch);
    } else {
      if (current.length >= 4) results.push(current);
      current = '';
    }

    // avança i para após o bloco consumido (leb128 + 0x36 + align + offset)
    i = j; // próximo loop vai incrementar +1
  }

  if (current.length >= 4) results.push(current);

  // deduplica e retorna
  return [...new Set(results)];
}

// ── Decompiler ───────────────────────────────────────────────
const OPCODE_MAP = {
  0x00:'unreachable', 0x01:'nop',
  0x02:'block',       0x03:'loop',         0x04:'if',        0x05:'else', 0x0B:'end',
  0x0C:'br',          0x0D:'br_if',        0x0E:'br_table',  0x0F:'return',
  0x10:'call',        0x11:'call_indirect',
  0x1A:'drop',        0x1B:'select',
  0x20:'local.get',   0x21:'local.set',    0x22:'local.tee',
  0x23:'global.get',  0x24:'global.set',
  0x28:'i32.load',    0x29:'i64.load',     0x2A:'f32.load',  0x2B:'f64.load',
  0x36:'i32.store',   0x37:'i64.store',    0x38:'f32.store', 0x39:'f64.store',
  0x3F:'memory.size', 0x40:'memory.grow',
  0x41:'i32.const',   0x42:'i64.const',    0x43:'f32.const', 0x44:'f64.const',
  0x45:'i32.eqz',     0x46:'i32.eq',       0x47:'i32.ne',
  0x48:'i32.lt_s',    0x49:'i32.lt_u',     0x4A:'i32.gt_s',  0x4B:'i32.gt_u',
  0x6A:'i32.add',     0x6B:'i32.sub',      0x6C:'i32.mul',
  0x6D:'i32.div_s',   0x6E:'i32.div_u',
  0x71:'i32.and',     0x72:'i32.or',       0x73:'i32.xor',
  0x74:'i32.shl',     0x75:'i32.shr_s',    0x76:'i32.shr_u',
  0x7C:'i64.add',     0x7D:'i64.sub',      0x7E:'i64.mul',
  0x92:'f32.add',     0x93:'f32.sub',      0x94:'f32.mul',
  0xA0:'f64.add',     0xA1:'f64.sub',      0xA2:'f64.mul',
};

export function decompileFunction(buffer, offset, size) {
  const end = offset + size;
  const lines = [];
  let indent = 1;
  let i = offset;

  const { value: localCount, bytesRead: lb } = readULEB128(buffer, i);
  i += lb;
  for (let l = 0; l < localCount; l++) {
    const { bytesRead: cb } = readULEB128(buffer, i); i += cb; i++;
  }

  const pad = (n) => '  '.repeat(Math.max(0, n));

  while (i < end) {
    const op   = buffer[i++];
    const name = OPCODE_MAP[op];

    if (op === 0x0B) {
      indent = Math.max(0, indent - 1);
      lines.push(`${pad(indent)}end`);
      continue;
    }
    if (op === 0x05) {
      lines.push(`${pad(indent - 1)}else`);
      continue;
    }
    if ([0x02,0x03,0x04].includes(op)) {
      lines.push(`${pad(indent)}${name ?? `0x${op.toString(16)}`}`);
      indent++; i++; continue;
    }
    if ([0x0C,0x0D,0x10,0x20,0x21,0x22,0x23,0x24].includes(op)) {
      const { value, bytesRead } = readULEB128(buffer, i); i += bytesRead;
      lines.push(`${pad(indent)}${name ?? `0x${op.toString(16)}`} ${value}`);
      continue;
    }
    if ([0x28,0x29,0x2A,0x2B,0x36,0x37,0x38,0x39].includes(op)) {
      const { bytesRead: ab } = readULEB128(buffer, i); i += ab;
      const { value: off, bytesRead: ob } = readULEB128(buffer, i); i += ob;
      lines.push(`${pad(indent)}${name ?? `0x${op.toString(16)}`} offset=${off}`);
      continue;
    }
    if (op === 0x41) {
      const { value, bytesRead } = readULEB128(buffer, i); i += bytesRead;
      lines.push(`${pad(indent)}i32.const ${value}`); continue;
    }
    if (op === 0x42) {
      const { value, bytesRead } = readULEB128(buffer, i); i += bytesRead;
      lines.push(`${pad(indent)}i64.const ${value}`); continue;
    }

    if (name) lines.push(`${pad(indent)}${name}`);
    else       lines.push(`${pad(indent)}0x${op.toString(16).padStart(2,'0')}  ;; unknown`);

    if (lines.length > 120) {
      lines.push(`${pad(indent)};; ... (truncated)`);
      break;
    }
  }
  return lines.join('\n');
}

// ── Traduções / Internacionalização ──────────────────────────
export const T = {
  en: {
    dropLabel:        'Drop your .wasm file here',
    dropSub:          'or click to select',
    statusIdle:       'No file loaded.',
    statusSmall:      'File too small to be a valid WASM.',
    statusInvalid:    'Invalid signature. This is not a WebAssembly binary.',
    statusOk:         (n) => `Analysis complete -- ${n} sections detected.`,
    metaTitle:        'File Metadata',
    metaName:         'Name',
    metaSize:         'Size',
    metaMagic:        'Magic Bytes',
    metaVer:          'Binary Version',
    sectTitle:        'Detected Sections',
    sectName:         'Name',
    sectId:           'ID',
    sectOffset:       'Offset',
    sectBytes:        'Bytes',
    opTitle:          'Execution Profile -- Opcodes',
    opFlow:           'Control Flow',
    opMem:            'Memory',
    opMath:           'Math',
    diagOk:           'Behavioral profile within normal parameters. No anomalies detected.',
    diagAviso:        'High memory manipulation detected. Massive data structure processing.',
    diagPerigo:       'High math density detected. Possible cryptographic algorithm or hidden mining.',
    strTitle:         'Extracted Strings -- Threat Intelligence',
    strEmpty:         'No strings found in this category.',
    filtAll:          'All',
    filtUrls:         'URLs',
    filtKeys:         'Keys/Tokens',
    filtFlags:        'CTF Flags',
    decompTitle:      'Function Decompiler',
    decompSelect:     'Select a function to decompile',
    decompBtn:        'Decompile',
    copyBtn:          'Copy',
    downloadBtn:      'Download TXT',
    footerOnline:     'System online',
    footerSub:        'WASM GUARDIAN v2.0',
    footerLocal:      'Local analysis -- no data is transmitted',
    tagLabels:        { CRITICAL:'CRITICAL', CRYPTO:'CRYPTO', LOGIC:'LOGIC', STANDARD:'STANDARD' },
    entropyTitle:     'Shannon Entropy',
    entropyHigh:      'HIGH ENTROPY: possible obfuscation or compression detected',
    dynStrTitle:      'Dynamic String Reconstruction -- Opcode Patterns',
  },
  pt: {
    dropLabel:        'Solte o arquivo .wasm aqui',
    dropSub:          'ou clique para selecionar',
    statusIdle:       'Nenhum arquivo carregado.',
    statusSmall:      'Arquivo muito pequeno para ser um WASM valido.',
    statusInvalid:    'Assinatura invalida. Este nao e um binario WebAssembly.',
    statusOk:         (n) => `Analise concluida -- ${n} secoes detectadas.`,
    metaTitle:        'Metadados do Arquivo',
    metaName:         'Nome',
    metaSize:         'Tamanho',
    metaMagic:        'Magic Bytes',
    metaVer:          'Versao do Binario',
    sectTitle:        'Secoes Detectadas',
    sectName:         'Nome',
    sectId:           'ID',
    sectOffset:       'Offset',
    sectBytes:        'Bytes',
    opTitle:          'Perfil de Execucao -- Opcodes',
    opFlow:           'Fluxo de Controle',
    opMem:            'Memoria',
    opMath:           'Matematica',
    diagOk:           'Perfil comportamental dentro do padrao normal. Nenhuma anomalia detectada.',
    diagAviso:        'Alta manipulacao de memoria RAM. Processamento massivo de estruturas de dados.',
    diagPerigo:       'Alta densidade matematica detectada. Possivel algoritmo criptografico ou mineracao oculta.',
    strTitle:         'Strings Extraidas -- Threat Intelligence',
    strEmpty:         'Nenhuma string encontrada nesta categoria.',
    filtAll:          'Todos',
    filtUrls:         'URLs',
    filtKeys:         'Chaves/Tokens',
    filtFlags:        'Flags CTF',
    decompTitle:      'Decompilador de Funcoes',
    decompSelect:     'Selecione uma funcao para decompilar',
    decompBtn:        'Decompilar',
    copyBtn:          'Copiar',
    downloadBtn:      'Baixar TXT',
    footerOnline:     'Sistema online',
    footerSub:        'WASM GUARDIAN v2.0',
    footerLocal:      'Analise local -- nenhum dado e enviado',
    tagLabels:        { CRITICAL:'CRITICA', CRYPTO:'CRIPTO', LOGIC:'LOGICA', STANDARD:'PADRAO' },
    entropyTitle:     'Entropia de Shannon',
    entropyHigh:      'ALTA ENTROPIA: possivel ofuscacao ou compressao detectada',
    dynStrTitle:      'Reconstrucao Dinamica de Strings -- Padroes de Opcodes',
  },
};