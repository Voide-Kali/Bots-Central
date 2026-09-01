# Caderno técnico confidencial da possível invenção

> Documento interno. Mantenha o repositório privado e não use este texto como
> reivindicação de patente sem busca de anterioridade e revisão profissional.

## Núcleo técnico em avaliação

Intertravamento de segurança entre uma solicitação em linguagem natural e uma
ação privilegiada no endpoint. O modelo de IA somente propõe uma ação; um
motor determinístico separado decide se ela pode ser confirmada e executada.

O problema técnico investigado é impedir execução não autorizada, replay,
troca de parâmetros, exfiltração e atuação sobre um contexto de máquina que
mudou entre a proposta e a confirmação.

## Registro canônico da ação

Uma ação candidata deve poder ser representada sem texto livre por campos como:

- versão do esquema e da política;
- tipo de capacidade;
- parâmetros normalizados;
- identificadores do chat, usuário, dispositivo e instalação;
- fingerprint do contexto relevante do sistema;
- nonce aleatório, emissão e expiração;
- digest canônico de todos os campos anteriores.

Senhas, tokens, conteúdo de arquivos e o comando completo não entram na trilha
de auditoria.

## Máquina de estados proposta

```text
proposta
  -> política_validada
  -> aguardando_confirmação
  -> confirmada
  -> contexto_revalidado
  -> executando
  -> concluída | falhou

aguardando_confirmação -> expirada | cancelada
qualquer divergência de digest/contexto -> recusada
```

## Invariantes

1. A saída da IA nunca é executada diretamente.
2. Uma capacidade desativada localmente não pode gerar nem consumir pendência.
3. Confirmação só vale para o mesmo usuário, chat, ação, parâmetros e instalação.
4. Um nonce pode ser consumido no máximo uma vez, inclusive sob concorrência.
5. A expiração é verificada na criação, confirmação e execução.
6. Mudança do contexto protegido invalida a ação antes do efeito no sistema.
7. Caminhos resolvidos por symlink continuam dentro da raiz autorizada.
8. Auditoria não registra material que permita reproduzir um segredo.

## Baselines para comparação

- agente que executa diretamente texto produzido pelo modelo;
- bot com confirmação simples vinculada somente ao chat;
- allowlist sem digest, expiração ou revalidação de contexto;
- implementação com e sem consumo atômico da pendência.

## Experimentos mínimos

| Experimento | Medida principal | Resultado esperado |
|---|---|---|
| 1.000 prompts adversariais | ações indevidas executadas | zero |
| Confirmação repetida e concorrente | execuções por nonce | no máximo uma |
| Reinício em cada transição | perda e replay | nenhum replay crítico |
| Alteração de parâmetro após confirmação | ações recusadas | 100% |
| Troca de usuário no mesmo grupo | ações recusadas | 100% |
| Symlink e `..` em exportação | escapes da raiz | zero |
| Mudança de rota/gateway antes da ação | atuação no contexto antigo | zero |
| Falha do armazenamento durante consumo | estado parcial | zero |

Registrar também latência p50/p95, uso de CPU, falsos positivos, falsos
negativos e versões exatas de hardware, SO, bibliotecas e políticas.

## Evidência a preservar por rodada

- data, responsável e objetivo;
- commit e hash do manifesto do runtime;
- configuração redigida e versão da política;
- script e semente do teste;
- dados brutos, saída esperada e observada;
- falhas e resultados negativos;
- decisão técnica tomada após o experimento.

## Riscos de anterioridade a pesquisar

- ChatOps e aprovação em duas etapas;
- capability-based security e policy engines;
- PAM, step-up authentication e tokens de uso único;
- proteção contra prompt injection em agentes;
- DLP, sandboxing e execução remota privilegiada;
- logs encadeados e trilhas resistentes a adulteração;
- NAC e vinculação de ações ao contexto de rede.

O diferencial não deve ser apenas reunir técnicas conhecidas. É necessário
demonstrar uma interação técnica específica e um efeito mensurável que não seja
uma consequência óbvia da combinação.
