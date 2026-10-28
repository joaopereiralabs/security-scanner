# SecurityScanner

**João Pereira Labs · Security Visibility Through Intelligent Analysis**

Uma ferramenta de terminal para entender quais serviços TCP estão expostos em um
ambiente autorizado e organizar os resultados em relatórios que você pode consultar depois.

O SecurityScanner usa o Nmap para fazer as verificações, mantém um histórico local e
exporta relatórios em HTML, JSON e Markdown. Tudo roda na sua máquina, sem conta externa
ou servidor próprio para a ferramenta.

**Versão atual: 0.2.0, em desenvolvimento.** A varredura TCP, a importação de XML e os
relatórios funcionam. Análise HTTP/TLS e interface interativa Textual são os próximos
passos; ainda não fazem parte desta versão.

[English documentation](README.en.md) · [Roadmap](docs/ROADMAP.md) · [Validação](docs/VALIDATION.md)

## Para que serve?

Você pode usar o projeto para conferir as portas de um servidor seu, registrar os
serviços encontrados e comparar duas verificações feitas com o mesmo escopo.
Também pode importar um XML do Nmap e gerar um relatório sem enviar tráfego ao alvo.

Uma porta aberta não é, por si só, uma vulnerabilidade. Por isso, os resultados atuais
são observações informativas: a ferramenta não inventa CVEs nem afirma que um sistema
foi comprometido porque encontrou uma versão de software.

| Recurso | Situação |
|---|---|
| CLI com diagnóstico do ambiente | Disponível |
| Escopo explícito e confirmação de autorização | Disponível |
| Portas TCP e identificação opcional de serviços/versões | Disponível, com Nmap |
| Importação passiva de XML | Disponível, sem conexões ao alvo |
| Histórico SQLite e comparação | Disponível |
| Relatórios HTML, JSON e Markdown | Disponível |
| Cabeçalhos HTTP, cookies e certificados TLS | Planejado para v0.3 |
| Interface Textual | Planejada para v0.5 |
| Correlação com avisos públicos de segurança | Planejada, sem data definida |

## Antes de instalar

Você vai precisar de **Python 3.11 ou superior** e **Nmap** para as varreduras ativas.
O Git é necessário se optar por clonar o repositório. A importação passiva funciona sem Nmap.

O projeto tem Kali Linux como plataforma principal desejada, com Debian e Ubuntu no
escopo de compatibilidade. A validação local registrada foi feita no Windows com Python
3.12.10 e Nmap 7.991. O workflow do GitHub está configurado para Ubuntu e Python 3.11–3.13;
consulte a aba [Actions](https://github.com/joaopereiralabs/security-scanner/actions)
para ver o resultado de cada execução.

## Instalação no Kali, Debian ou Ubuntu

```bash
sudo apt update
sudo apt install -y python3 python3-venv git nmap

git clone https://github.com/joaopereiralabs/security-scanner.git
cd security-scanner

python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .

securityscanner doctor
securityscanner --help
```

O `sudo` é usado somente para instalar os pacotes do sistema. Execute o SecurityScanner
como usuário comum; a varredura utiliza TCP connect e não exige execução como root.

## Instalação no Windows — PowerShell

Com Python, Git e Nmap instalados e disponíveis no PATH:

```powershell
git clone https://github.com/joaopereiralabs/security-scanner.git
cd security-scanner

python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\securityscanner.exe doctor
```

Para usar os exemplos abaixo com comandos curtos, crie esta função na janela atual:

```powershell
function securityscanner { & .\.venv\Scripts\securityscanner.exe @args }
securityscanner --help
```

Essa função funciona enquanto você estiver na pasta do projeto e existir naquela sessão.
Ao abrir outro PowerShell, entre na pasta e crie a função novamente, ou use o caminho
completo `.\.venv\Scripts\securityscanner.exe` no lugar de `securityscanner`.
Não é necessário alterar a política de execução do PowerShell.

**Prefere baixar o ZIP?** Use **Code → Download ZIP** na página do repositório, extraia o
arquivo e abra o terminal na pasta que contém `pyproject.toml`. Continue a partir da
criação do ambiente virtual. A instalação do pacote pelo nome no PyPI não é pressuposta.

## Primeiro teste: conhecer o fluxo sem varrer nada

O projeto inclui um XML com dados fictícios, identificado como exemplo. Importe-o:

```bash
securityscanner scan --profile passive --import-xml examples/synthetic-nmap.xml
securityscanner history
```

Você verá um serviço em `192.0.2.10:443`. Esse endereço está dentro do arquivo de exemplo:
**nenhuma conexão foi feita com ele**. O modo passivo lê o XML e grava os resultados locais.
Ele não resolve DNS nem executa o Nmap.

Cada execução recebe um ID. Copie esse valor para gerar o relatório, substituindo `SCAN_ID`:

```bash
securityscanner report --scan-id SCAN_ID --format html --output exemplo.html
```

Abra `exemplo.html` no navegador. No PowerShell:

```powershell
Start-Process .\exemplo.html
```

Esta é uma captura real do relatório renderizado com os dados fictícios:

![Relatório HTML com dados sintéticos](docs/report-preview.png)

O HTML funciona offline, sem CDN, e tem estilo de impressão. Os exemplos completos estão
em [HTML](examples/synthetic-report.html), [JSON](examples/synthetic-report.json) e
[Markdown](examples/synthetic-report.md). A captura acima é do relatório, não de uma TUI.

## Verificar o próprio computador

```bash
securityscanner scan --target 127.0.0.1 --allow 127.0.0.1 --authorized --profile basic
```

Por padrão, são verificadas as portas `22,80,443,8080,8443`. Se aparecer
`completed; 0 open TCP services`, a execução terminou e não observou portas abertas
**nesse conjunto**. Isso não significa que todas as portas do computador foram verificadas.

Para escolher portas e tentar identificar as versões:

```bash
securityscanner scan --target 127.0.0.1 --allow 127.0.0.1 --authorized --ports 80,443,8000 --versions
```

Sem `--versions`, o nome do serviço pode ser apenas o rótulo associado à porta na tabela
do Nmap. Com essa opção, são enviadas sondagens de aplicação de intensidade 0. Mesmo assim,
a identificação pode ficar desconhecida ou o servidor pode fornecer um banner incorreto.

## Verificar um servidor ou domínio autorizado

Troque `seu-dominio.com` pelo domínio que você tem permissão para avaliar:

```bash
securityscanner scan --target seu-dominio.com --allow seu-dominio.com --authorized --ports 80,443
```

Use somente o hostname, sem `https://`, caminhos ou parâmetros. O `--target` indica o
destino; o `--allow` delimita o escopo; `--authorized` registra sua confirmação de permissão.
As três informações são necessárias para a verificação ativa, inclusive em localhost.

Um hostname autorizado permite os IPs resolvidos inicialmente para ele. A aplicação
revalida o DNS antes de cada tarefa e passa somente IPs fixados ao Nmap. Se o domínio
estiver atrás de uma CDN ou hospedagem compartilhada, o destino pode ser a infraestrutura
do provedor: verifique se esses endereços estão abrangidos pela autorização.

**Nesta versão, verificar as portas de um site não equivale a auditar a aplicação web.**
Não há análise de cabeçalhos, certificados, formulários, SQL injection ou XSS.

## Histórico, relatórios e comparação

```bash
securityscanner history
securityscanner report --scan-id SCAN_ID --format json --output auditoria.json
securityscanner report --scan-id SCAN_ID --format markdown --output auditoria.md
securityscanner report --scan-id SCAN_ID --format html --output auditoria.html
securityscanner compare --scan-a ID_ANTERIOR --scan-b ID_NOVO
```

Substitua os IDs pelos valores reais do histórico. Um arquivo existente não é sobrescrito;
escolha outro nome para guardar a próxima versão.

A comparação exige execuções concluídas com o mesmo perfil, IPs resolvidos, portas e modo
de detecção de versões. Ela apresenta serviços e findings novos, persistentes e não mais
observados. Um resultado que desapareceu não prova que o problema foi corrigido: pode ter
havido uma mudança de conectividade. Em XMLs importados, a cobertura original não é verificada.

## Limites e armazenamento

- No máximo 16 IPs resolvidos e 32 portas TCP explícitas por auditoria; sem intervalos/CIDRs.
- Uma tarefa por vez, com timeout padrão de 90 segundos por IP, configurável de 5 a 300.
- Taxa padrão de 10 pacotes/s na fase de varredura, configurável de 1 a 20 com `--max-rate`.
  Essa opção do Nmap não estabelece um orçamento estrito para todas as sondagens de versão.
- `Ctrl+C` cancela a execução. Resultados de tarefas já concluídas podem ficar no histórico;
  execuções canceladas ou com falha não entram na comparação.
- Nenhuma telemetria ou consulta a bases externas de vulnerabilidades está implementada.
  Verificações ativas por hostname utilizam o DNS configurado no sistema.

O histórico e o log de auditoria ficam em `~/.local/share/securityscanner` por padrão.
No Linux, `XDG_DATA_HOME` é respeitado. Você pode escolher outra pasta com
`SECURITYSCANNER_DATA_DIR`. Os dados são locais, sem criptografia, e os logs ainda não
têm rotação automática. Proteja a pasta e revise as evidências antes de compartilhar relatórios.

## Quando algo não sair como esperado

| Situação | O que fazer |
|---|---|
| Nmap não encontrado | Instale-o, confira o PATH e execute `doctor` novamente. |
| Destino fora do escopo | Confira se o hostname/IP aparece exatamente em `--target` e `--allow`. |
| DNS mudou depois da aprovação | Revise os IPs do domínio antes de iniciar outra execução. |
| Nenhuma porta aberta | Confira as portas escolhidas, o serviço e a conectividade; não é automaticamente uma falha. |
| Versão desconhecida | É um resultado possível mesmo com `--versions`; não atribua uma versão por suposição. |
| Timeout | Reduza o conjunto de portas ou ajuste `--timeout` dentro dos limites. |
| XML rejeitado | Use um XML completo e bem-sucedido do Nmap, com até 8 MiB. |
| Relatório já existe | Escolha outro nome em `--output`. |
| `ui` ou perfil `web` indisponível | São recursos planejados e ainda não implementados. |

## Testes e desenvolvimento

Instale as dependências de desenvolvimento no ambiente virtual:

```bash
python -m pip install -e '.[dev]'
ruff check .
ruff format --check .
mypy
pytest -q
python -m build
```

No Windows, sem ativar a venv, use `.\.venv\Scripts\python.exe -m pytest -q` e os executáveis
`ruff.exe` e `mypy.exe` que ficam em `.\.venv\Scripts\`.

A suíte padrão não depende de alvos públicos. O teste de integração real é opcional: ele
cria um servidor temporário no loopback e executa o Nmap contra esse único destino.

```bash
# Linux: incluir o teste real com Nmap
SECURITYSCANNER_NMAP_TEST=1 pytest -q
```

```powershell
# Windows: incluir o teste real com Nmap
$env:SECURITYSCANNER_NMAP_TEST="1"
.\.venv\Scripts\python.exe -m pytest -q
Remove-Item Env:SECURITYSCANNER_NMAP_TEST
```

A validação local da v0.2.0 registrou **86 testes aprovados**, incluindo essa integração.
Sem habilitá-la, o resultado registrado foi **85 aprovados e 1 ignorado**. O ambiente,
as correções feitas durante a revisão e as limitações estão em
[docs/VALIDATION.md](docs/VALIDATION.md). Esses números descrevem aquela validação;
o resultado atual de CI deve ser consultado em Actions.

## Como o código está organizado

```text
src/securityscanner/
├── cli.py                 # Comandos e mensagens do terminal
├── config.py              # Configuração e limites
├── core/                  # Escopo, modelos, execução e comparação
├── scanners/              # Integração com Nmap e leitura de XML
├── analyzers/             # Conversão de observações em findings
├── storage/               # Histórico SQLite
├── reports/               # HTML, JSON e Markdown
└── utils/                 # Log de auditoria
```

A CLI chama o orquestrador, que valida o escopo antes de executar o scanner.
Os resultados são convertidos em modelos, persistidos e usados na geração de relatórios.
Os detalhes e o modelo de ameaças estão em [ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Próximos passos

O próximo marco é a **v0.3: análise HTTP e TLS**, com limites de requisições, validação
de redirecionamentos e testes locais de certificados. Depois vêm a evolução dos
relatórios e a interface Textual. A v1.0 depende de validação mais ampla e revisão de segurança.

O [roadmap](docs/ROADMAP.md) separa o que está entregue, antecipado parcialmente e planejado.
Para contribuir, leia [CONTRIBUTING.md](CONTRIBUTING.md). Problemas de segurança da própria
ferramenta devem seguir [SECURITY.md](SECURITY.md).

## Autor e licença

Desenvolvido por **João Pereira** · [@joaopereiralabs](https://github.com/joaopereiralabs).

Distribuído sob a [licença MIT](LICENSE). O Nmap é uma dependência externa e mantém sua
própria licença; ele não é distribuído junto com este projeto.

Use somente em sistemas próprios ou com autorização explícita. A confirmação na CLI
registra a declaração do operador; ela não verifica a existência dessa autorização.
