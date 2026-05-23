# WASM Guardian

> Analisador estático e local para engenharia reversa inicial de binários WebAssembly.

**Acesse em:** [williankfa.github.io/wasm-guardian](https://williankfa.github.io/wasm-guardian/)

---

## Visão Geral

WASM Guardian é uma ferramenta de inspeção de arquivos `.wasm` que roda inteiramente no navegador, sem depender de nenhum servidor externo. O arquivo carregado é processado diretamente na memória local através de estruturas nativas do JavaScript — nenhum byte do seu binário trafega pela rede.

O projeto nasceu dos meus estudos práticos em segurança da informação e análise de malware. Queria entender como um binário WebAssembly é estruturado por dentro — como as instruções de baixo nível se organizam, onde ficam as strings, o que os opcodes revelam sobre o comportamento de um programa — e a melhor forma que encontrei de consolidar esse aprendizado foi construindo a própria ferramenta de análise.

---

## Funcionalidades

**Validação estrutural**
Lê os primeiros bytes do arquivo e confirma a assinatura mágica do WebAssembly antes de iniciar qualquer processamento. Arquivos inválidos são rejeitados imediatamente.

**Mapeamento de seções**
Identifica os blocos internos do binário — Type, Import, Function, Code, Data, entre outros — exibindo o offset exato e o tamanho de cada seção. É o equivalente a enxergar o esqueleto do arquivo antes de entrar em detalhes.

**Perfil de opcodes**
Varre a seção de código e categoriza as instruções em três grupos: fluxo de controle, operações de memória e lógica matemática. A partir da densidade de cada grupo, gera um diagnóstico comportamental — uma concentração muito alta de operações matemáticas, por exemplo, pode indicar um algoritmo criptográfico ou minerador oculto.

**Análise de entropia (Shannon)**
Calcula a entropia do arquivo inteiro. Um valor acima de 7.5 pode indicar que o binário passou por ofuscação ou compressão — o que, em um contexto de auditoria, justifica uma investigação mais cuidadosa.

**Taint Analysis**
Rastreia caminhos suspeitos entre importações externas e funções marcadas como críticas ou criptográficas, mapeando estaticamente se alguma entrada externa alcança partes sensíveis do código.

**Extração de strings e filtros**
Captura todas as sequências de caracteres legíveis do binário com filtros por categoria: URLs, chaves e tokens de autenticação, e flags de desafios CTF.

**Reconstrução dinâmica de strings**
Detecta strings que não estão armazenadas diretamente no binário, mas são montadas em tempo de execução via sequências de opcodes — uma técnica comum em código ofuscado.

**Decompilação em pseudocódigo**
Converte as instruções brutas do bytecode em texto indentado e legível, facilitando a leitura manual de loops, desvios condicionais e chamadas de função.

**Exportação de relatório**
Gera um arquivo `.md` com todos os resultados da análise, pronto para ser aberto no Notion ou Obsidian e complementado com anotações manuais.

**Interface bilíngue**
Alternância entre inglês e português sem recarregar a página.

---

## Limitações Conhecidas

Por se tratar de um analisador estático baseado em heurísticas de contagem e busca de padrões, a ferramenta possui restrições que pretendo endereçar em versões futuras.

O caso mais evidente são os falsos positivos na marcação automática de funções. O algoritmo atual classifica uma função como `CRITICAL` com base na presença isolada de certos opcodes — como `call_indirect`. O problema é que esse mesmo opcode aparece com frequência em frameworks legítimos e motores de jogos, sem nenhuma intenção maliciosa. Corrigir isso de forma confiável exige uma análise de fluxo de dados real, o que está planejado para versões futuras.

Esta é uma versão inicial, voltada para aprendizado e experimentação. A precisão vai melhorar com o tempo.

---

## Stack

| Camada | Tecnologia |
|---|---|
| Lógica de análise | JavaScript ES6+ — `FileReader`, `Uint8Array` |
| Interface | React.js |
| Estilo | HTML5, CSS3 |
| Deploy | GitHub Pages |

---

## Rodando Localmente

Requisito: Node.js instalado na sua máquina.

```bash
# Clone o repositório
git clone https://github.com/williankfa/wasm-guardian.git

# Acesse a pasta do projeto
cd wasm-guardian

# Instale as dependências
npm install

# Inicie o servidor de desenvolvimento
npm start
```

O projeto abrirá automaticamente no seu navegador padrão em `http://localhost:3000`.

---

## Licença

Este projeto é de código aberto e foi desenvolvido para fins educacionais.
