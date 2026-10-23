# Ben 10 - projeto experimental

Abra `Jogar\Ben10.exe` para iniciar o teste. Mantenha os dois executaveis juntos.
Ainda nao e uma versao jogavel: a interface aparece parcialmente, mas a
inicializacao ainda nao avanca e faltam textos. O componente MP3 foi integrado
em `Jogar/firmware`; o erro de arquivo ausente foi corrigido, mas isso nao
confirma reproducao de audio nem resolve sozinho o painel parado.

O iniciador impede duas aberturas simultaneas e guarda os registros por sessao.

## Organizacao

- Jogar: iniciador, runtime e registros de cada teste em sessoes/.
- Ben10_Port: codigo recompilado, metadados e compilacao original preservada.
- ps3recomp: SDK original. Caminho preservado porque a compilacao depende dele.
- PS3_GAME: copia original dos dados; nao foi excluida como duplicata.
- EBOOT.elf: programa original usado pelo executavel de teste; nao mover.
- Ferramentas: script de preparacao do ELF.
- Backups: arquivo RAR original e compilacoes incompletas, recuperaveis.
- Backups/Registros antigos: logs soltos que estavam na raiz.

Os dados lidos pelo teste estao em
`E:\Ben 10 - Ultimate Alien - Cosmic Destruction (USA) (EnFrEs)`.
Nao apague essa pasta nem EBOOT.elf.

A organizacao nao corrige o bloqueio de inicializacao. Nenhum dump, save,
codigo-fonte ou compilacao original foi apagado.
