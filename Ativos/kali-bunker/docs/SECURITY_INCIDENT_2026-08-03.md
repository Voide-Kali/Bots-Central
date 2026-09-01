# Registro de incidente: credencial Pushover em documento legado

## Resumo

Em 3 de agosto de 2026, uma revisão pré-publicação encontrou identificadores
Pushover com formato de credencial dentro de `manual_seguranca_kali.pdf`. O
arquivo já existia no histórico remoto enquanto o repositório estava público.
Os valores não são reproduzidos neste documento.

## Contenção executada

- os dois repositórios foram alterados para privados;
- o PDF foi removido da versão atual;
- o nome do artefato foi bloqueado no `.gitignore`;
- o scanner passou a extrair texto de PDFs e detectar credenciais Pushover;
- a configuração operacional atual não possui `PUSHOVER_TOKEN` ativo;
- alertas e correções automáticas do Dependabot foram habilitados.

## Ações ainda necessárias pelo titular

1. Revogar ou regenerar o token no painel oficial do Pushover, mesmo que pareça
   antigo ou sem uso.
2. Preservar uma cronologia privada da exposição antes de qualquer reescrita,
   pois ela pode ser relevante para análise jurídica de divulgação anterior.
3. Depois da preservação e da orientação jurídica, decidir se o histórico Git
   remoto será reescrito e coordenar a atualização de clones e forks.

Reescrever o Git não revoga a credencial nem remove cópias externas; rotação é
a ação de segurança essencial.
