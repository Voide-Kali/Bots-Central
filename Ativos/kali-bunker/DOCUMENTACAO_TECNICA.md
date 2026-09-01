# Documentacao tecnica do Kali Bunker

Este documento explica o sistema em blocos, por arquivo e por funcao.
Ele e mais util para manutencao do que uma leitura literal linha por linha, porque o codigo do bot tem muitos caminhos condicionais.

## Visao geral

O controle remoto tem duas interfaces e um motor compartilhado:

1. `/home/voide/Projetos/gmail-telegram-bot/bot.py`
   - Interface com Telegram.
   - Exibe menus.
   - Recebe mensagens.
   - Decide quando criar uma acao pendente.
   - Executa webcam, shell, envio de arquivos, servicos e monitoramento.

2. `/home/voide/Kali-Bunker-main/telegram_control.py`
   - Interface Telegram independente e opcional do Kali Bunker.
   - Oferece painel, serviços, rede, terminal, arquivos, IA e cofre.
   - Executa o polling quando `kali-bunker-telegram.service` esta ativo.

3. `/home/voide/Kali-Bunker-main/remote_control.py`
   - Motor de IA local e online.
   - Gera resposta de conversa.
   - Monta planos para terminal, webcam, arquivo, pacote e servico.
   - Mantem historico curto da conversa da IA.

## Fluxo principal da IA

1. O usuario escreve uma mensagem normal ou usa `/ia`.
2. `bot.py` ou `telegram_control.py` chama `ai_assistant()`.
3. `remote_control.py` tenta responder localmente primeiro quando existe fallback.
4. Se a resposta exigir acao real, o bot cria uma pendencia com codigo de confirmacao.
5. O usuario confirma manualmente.
6. O bot executa a acao.

## Arquivo `remote_control.py`

### Funcoes de base

- `_normalize_text()`
  - Remove acentos e normaliza texto.
  - Serve para comparar frases de forma confiavel.

- `_extract_topic()`
  - Isola o tema pedido pelo usuario.
  - Usa prefixos como `estudar`, `explicar`, `resumir` e `quiz`.

- `_study_plan_response()`
  - Responde pedidos de estudo sem precisar da OpenAI.
  - Cobre plano de estudo, resumo, explicacao e quiz.

### Persistencia

- `_load_pending()` e `_save_pending()`
  - Leem e gravam a fila de acoes pendentes.

- `_load_ai_chat_history()` e `_save_ai_chat_history()`
  - Leem e gravam o historico curto da IA por chat.

- `remember_ai_chat()`
  - Guarda pares de pergunta e resposta.

- `clear_ai_chat_history()`
  - Remove o historico de um chat.

### Acoes remotas

- `create_pending()`
  - Gera um codigo curto e registra a acao que aguarda confirmacao.

- `pop_pending()`
  - Remove uma pendencia confirmada.

- `list_pending()`
  - Lista pendencias daquele chat.

- `cancel_pending()`
  - Cancela uma pendencia sem executar.

- `execute_shell()`
  - Executa comando de terminal.
  - Trunca a saida para evitar mensagens gigantes.

- `archive_for_send()`
  - Envia arquivo direto ou compacta pasta em `.tar.gz`.

- `install_package()`
  - Instala pacote via `apt-get`.

### Voz

- `ai_available()`
  - Diz se a chave da OpenAI esta disponivel e habilitada.

- `openai_response()`
  - Faz a chamada HTTP para a API.

- `fallback_plan()`
  - Detecta pedidos de terminal, arquivo, webcam, pacote e servico.
  - Hoje a webcam padrao e a integrada do notebook.

- `local_chat_response()`
  - Responde conversa simples sem usar a nuvem.

- `fallback_chat_response()`
  - Encaminha para a resposta local.

- `response_text()`
  - Extrai texto da resposta da API.

- `json_object_from_response()`
  - Converte a resposta da IA em JSON valido.

- `ai_assistant()`
  - Decide entre resposta local e online.
  - Garante que o resultado final tenha um formato valido.
  - Usa a memoria local da Voz como contexto quando existir.

- `utility_response()`
  - Detecta pedidos simples e responde localmente sem chamar a OpenAI.
  - Cobre estudo, produtividade, seguranca, texto, conversoes, templates e utilidades tecnicas.

- `add_ai_memory()`
  - Salva memoria permanente em `~/.local/state/kali-bunker/ai-memory.json`.
  - E usado quando o usuario ensina algo com frases como `lembre que ...`.

- `search_ai_memory()`
  - Busca informacoes guardadas na memoria local.

- `clear_ai_memory()`
  - Apaga a memoria permanente da Voz quando confirmado pelo usuario.

## Memoria local da Voz

A Voz tem dois tipos de memoria:

1. Conversa curta
   - Guarda as ultimas mensagens para contexto.
   - Pode ser limpa pelo botao `Limpar conversa`.

2. Memoria permanente
   - Guarda fatos ensinados pelo usuario e conteudos de arquivos.
   - Fica salva no PC em `~/.local/state/kali-bunker/ai-memory.json`.
   - Pode ser vista pelo botao `Memoria da Voz`.
   - Pode ser apagada com confirmacao.

## Cofre de senhas da Voz

O bot agora tem um cofre local de senhas acessivel pelo botao `Cofre de senhas` ou pelo atalho `/senhas`.

Arquivo principal:

- `voice_vault.py`
  - Guarda o cofre em `~/.local/state/kali-bunker/voice-password-vault.json`.
  - Usa PBKDF2-SHA256 para derivar chaves da senha mestra.
  - Usa AES-256-CTR via OpenSSL para cifrar o conteudo.
  - Usa HMAC-SHA256 para detectar senha mestra errada ou arquivo alterado.

Regras do cofre:

1. A senha mestra nao e salva em arquivo.
2. A senha mestra fica apenas na memoria do processo por 5 minutos apos desbloqueio.
3. O cofre bloqueia automaticamente quando a sessao expira ou quando o usuario toca em `Bloquear cofre`.
4. A lista de contas nao mostra senhas.
5. Buscar ou apagar uma senha cria uma acao pendente e exige confirmacao antes de revelar/remover.
6. A revelacao usa mensagem protegida do Telegram quando a API permite.
7. Ao receber senha mestra ou senha existente, o bot tenta apagar a mensagem do usuario no chat.

Fluxos disponiveis:

- desbloquear cofre
- listar contas
- gerar e salvar senha forte
- adicionar senha existente
- buscar senha
- apagar senha
- bloquear cofre

## Arquivos, PDFs, fotos e codigo

O bot aceita anexos enviados no Telegram:

- PDF
  - Extrai texto com `pdftotext`.
  - Salva o texto extraido na memoria local.

- Codigo longo e texto
  - Lê arquivos `.py`, `.js`, `.html`, `.json`, `.log`, `.sh`, `.md` e outros formatos comuns.
  - Guarda o conteudo na memoria local com limite configurado.

- Fotos
  - Registra metadados locais como formato, tamanho e dimensoes.
  - OCR nao esta ativo porque `tesseract` nao esta instalado neste PC.
  - Sem OCR/modelo visual online, texto dentro da imagem pode nao ser interpretado.

## Ferramentas de cyber seguranca

As ferramentas adicionadas ficam no menu `Cyber ferramentas` e sao defensivas:

- checklist de seguranca
- explicar comando Linux
- nmap seguro para rede local
- guia de sub-rede
- portas comuns
- analise de log
- explicar erro
- plano de laboratorio
- status das defesas e rede pelos menus existentes

Acoes reais de maquina continuam passando por confirmacao.

## Arquivo `telegram_control.py`

Esta e a interface independente executada por
`kali-bunker-telegram.service`.

- `run_loop()`
  - Busca atualizacoes na API do Telegram com retry progressivo.

- `handle_message()` e `handle_callback()`
  - Encaminham comandos, texto livre e botoes para as funcoes corretas.

- `handle_ai()` e `execute_pending_action()`
  - Usam `remote_control.py` e exigem confirmacao antes de acoes reais.

- `handle_vault_command()` e `handle_vault_callback()`
  - Operam o cofre por meio de `voice_vault.py`.

## Arquivo `state_utils.py`

- `atomic_write_json()`
  - Grava estado JSON em arquivo temporario exclusivo e faz substituicao
    atomica com permissao privada.

E usado pelo watchdog e pelo controle remoto para evitar arquivos parciais.

## Atalhos `kb` e `bunker-menu`

- `kb`
  - Encaminha argumentos para `bunkerctl.py`.

- `bunker-menu`
  - Oferece um menu interativo para resumo, diagnostico, servicos, rede,
    bloqueios e backup.

Ambos resolvem o caminho real do projeto mesmo quando chamados por link
simbolico.

## Arquivo `bot.py` do Gmail central

### Configuracao e orquestracao

- `validate_config()`
  - Garante variaveis obrigatorias.

- `project_path()`
  - Resolve caminhos relativos do projeto.

- `init_gmail_services()`
  - Autentica as contas Gmail configuradas.

- `start_bot()`
  - Monta o Telegram bot.
  - Registra handlers.
  - Inicia o polling.

### Painel e menus

- `main_keyboard()`
  - Menu principal.

- `show_dashboard()`, `show_gmail()`, `show_security()`, `show_system()`
  - Abrem as telas principais.

- `show_operations()`
  - Central de operacoes.

- `show_ai_menu()`
  - Mostra o estado da IA e explica como conversar.

### Fluxo da IA

- `process_voice_prompt()`
  - Recebe texto do usuario.
  - Chama a IA.
  - Cria pendencia quando a resposta pede acao real.

- `handle_voice_message()`
  - Encaminha mensagens comuns para a IA.

- `ai_command()`
  - Faz o mesmo via `/ia`.

- `execute_voice_pending()`
  - Executa a pendencia confirmada.

### Webcam

- `list_webcam_devices()`
  - Descobre dispositivos Video4Linux.

- `select_webcam_device()`
  - Prioriza camera integrada do notebook.
  - Usa score para evitar camera USB como preferencia.

- `configure_webcam_device()`
  - Aplica ajustes basicos com `v4l2-ctl`.

- `capture_webcam_photo()`
  - Usa `fswebcam`.
  - Faz melhoria basica da imagem com OpenCV quando disponivel.

- `show_webcam_confirm()` e `webcam_now()`
  - Pedem confirmacao e tiram a foto.

### Seguranca e protecoes

- `shell_command_rejected_reason()`
  - Bloqueia comandos perigosos antes da execucao.
  - Corta comandos destrutivos, de formacao de malware e de administracao sensivel.

- `error_text()`
  - Padroniza mensagens com codigo de erro.

### Canais de erro

Os codigos adicionados agora sao:

- `AI-001`
  - Mensagem vazia para a IA.

- `AI-002`
  - Falha no motor da IA.

- `SHELL-001`
  - Comando de terminal bloqueado pela camada de seguranca.

- `CAM-001`
  - Nenhuma camera foi encontrada.

- `CAM-002`
  - Camera encontrada, mas nenhuma capturavel foi aceita.

- `CAM-003`
  - Falha ao aplicar ajustes basicos da camera.

- `CAM-004`
  - Falha na captura com `fswebcam`.

- `CAM-005`
  - Foto nao foi gerada.

- `FILE-001`
  - Falha ao preparar arquivo ou pasta para envio.

- `PKG-001`
  - Falha ao instalar pacote.

- `SYS-001`
  - Falha ao controlar servico.

## Regras atuais da webcam

1. A camera do notebook e a preferida.
2. Camera USB nao e preferencia.
3. O bot nao tenta escolher por indice fixo.
4. O comportamento e por descricao do dispositivo e score.
5. Se a camera integrada falhar, a acao falha em vez de trocar para USB sem criterio.

## Regras atuais de seguranca

1. Toda acao real continua precisando de confirmacao.
2. Comandos destrutivos sao bloqueados antes de entrar na fila.
3. O bloqueio tambem e repetido na hora da execucao.
4. A IA conversa normalmente sem depender da OpenAI quando existe fallback local.
5. A resposta local e explicativa e orientada a estudo.

## Pontos de manutencao recomendados

1. Se a camera mudar de hardware, revise `webcam_device_score()`.
2. Se surgirem novos comandos perigosos, adicione ao filtro de `shell_command_rejected_reason()`.
3. Se novos tipos de acao forem criados, documente o novo codigo de erro aqui.
4. Se quiser mais explicacao visual, o proximo passo e gerar um diagrama de fluxo.
