# Relatório — Honeypot SSH com Cowrie

Rafael Pavan · novembro de 2026 · [Painel interativo](https://rafaelpavanf.github.io/honeypot-cowrie/)

## Resumo executivo

Um servidor SSH de mentira (honeypot Cowrie) ficou exposto na internet a partir de 9 de novembro de 2026 e **foi encontrado e atacado já no primeiro dia**. Até 25/11 (17 dias de coleta), registrou 88.230 tentativas de login de 2.336 IPs distintos, em 117 países.

Três achados se destacam:

1. Um único robô fez 35% das tentativas em 78 minutos, testando uma senha diferente a cada vez.
2. Os robôs testam se a shell é real antes de agir, e os arquivos enviados eram malware: mineradores de criptomoeda e um bot de IRC.
3. 30% dos pedidos de túnel miravam a porta de e-mail, tentativa provável de usar o servidor para enviar spam.

A única porta de entrada observada foi a adivinhação de senhas fracas. Trocar senhas por chaves SSH elimina esse caminho; firewall e restrição do tráfego de saída reduzem o resto.

## Objetivo e pergunta

O projeto responde a uma pergunta simples: **o que acontece, e com que rapidez, quando um servidor SSH aparece na internet?** Para isso, um servidor-isca (honeypot) sem nenhum uso legítimo foi colocado no ar e registrou tudo o que os visitantes tentaram fazer.

Como ninguém legítimo usa esse servidor, todo acesso a ele é suspeito. Isso permite observar com clareza três coisas: quem tenta entrar, com quais credenciais, e o que faz quando consegue.

O trabalho também serve como prática de ponta a ponta em segurança da informação: montar um ambiente seguro, coletar dados, analisá-los, comunicar os resultados e destruir o ambiente ao final.

## Ambiente e metodologia

O honeypot rodou numa máquina virtual alugada e dedicada só a isso, sem nenhum dado real, e foi destruída ao fim da coleta.

| Item | Configuração |
| --- | --- |
| Servidor | VPS Vultr (1 vCPU, 1 GB de RAM), Atlanta (EUA), Ubuntu 24.04 LTS |
| Honeypot | Cowrie (imagem oficial), em Docker, com volumes persistentes e limite de tamanho dos logs |
| Porta da isca | 22, a porta padrão do SSH, onde os robôs procuram |
| Administração | SSH em outra porta (22022), somente com chave, sem login de root, atrás de firewall (UFW) |
| Período | De 9 de novembro de 2026 até a cópia final do log (25/11/2026) |
| Horário | UTC em todos os dados e gráficos |

O Cowrie imita um servidor SSH e **aceita o login de propósito**, para deixar o visitante entrar numa shell falsa e registrar o que ele digita. Por isso quase todos os logins aparecem como aceitos; isso não indica falha de segurança.

**Cuidados éticos e de segurança.** A isca ficou separada de qualquer outro sistema. Nenhum arquivo enviado pelos invasores foi executado nem publicado: os arquivos foram identificados só pelo hash SHA-256 e consultados no VirusTotal sem enviar o arquivo. Nenhuma ação foi tomada contra os atacantes.

**Tratamento dos dados.** Os logs diários foram juntados e agregados com um script em Python (apoiado por jq na exploração inicial). Os acessos do próprio autor foram removidos antes da análise. **Nenhum endereço IP é publicado**: o painel e este relatório mostram só contagens. O país de origem foi obtido consultando cada IP no serviço gratuito ip-api.com, e só a contagem de IPs por país foi mantida.

## Resultados em números

Em 17 dias de coleta (9 a 25 de novembro de 2026, UTC), a isca registrou **88.230 tentativas de login vindas de 2.336 IPs distintos**.

| Métrica | Valor |
| --- | --- |
| Tentativas de login | 88.230 (99,5% aceitas pela isca, de propósito) |
| IPs distintos | 2.336, em 117 países |
| Sessões | 91.448, das quais 83.754 com comandos |
| Comandos digitados | 233.277 (121.044 diferentes) |
| Arquivos enviados à isca | 111 envios, 4 arquivos diferentes |
| Pedidos de túnel | 3.778 |

**Crescimento.** No primeiro dia, que começou às 18h21 UTC, já havia 977 tentativas de 6 IPs. O número de IPs distintos por dia subiu para 140 em 14/11 e chegou a 278 em 17/11. O maior pico veio em 23/11: 574 IPs distintos fizeram 2.988 tentativas, cerca de 5 por IP, um padrão compatível com varredura distribuída (muitos IPs, poucas tentativas cada).

**Concentração.** Os cinco IPs mais ativos respondem por 45,9% das tentativas, e um único IP por 35,2% (31.062). O pico de 16/11 (32.521 tentativas) é quase todo dele. Sem esse IP, o maior dia é 18/11, com 8.187 tentativas de só 70 IPs: poucos robôs insistentes, e não muitos.

**Origem.** Os Estados Unidos lideram com 563 IPs, cerca de um quarto do total (24%). Depois vêm a Coreia do Sul (136), a Rússia (133), a Índia (125) e o Brasil (108). O país é o do registro do IP, não necessariamente o de quem opera o robô.

**Credenciais.** O usuário `root` aparece em 53.321 tentativas (22.259 sem o IP mais ativo), seguido de `admin` (2.575) e `ubuntu` (2.176). As senhas mais usadas são `123456` (2.942), `123` (1.551), `1234` (1.307), `12345678` (871) e `1` (772). Os pares mais comuns são `root:admin` (248), `root:123456` (153) e `root:1234` (144).

**Comandos.** Dois comandos somam um terço do total: `echo -e "\x6F\x6B"` (31.061 vezes, todas do mesmo robô) e `uname -s -v -n -r -m` (46.576 vezes), seguidos de testes de shell e de `chmod +x` no arquivo enviado.

**Túneis.** Dos 3.778 pedidos para usar a isca como ponte, 1.131 (30%) miravam a porta 25, a do e-mail; seguem a porta 22 (814), a 2535 (674), a 443 (585) e a 80 (574).

## Achados principais

1. **Um robô testando se a isca aceita qualquer senha.** Em 1h18 (16/11), um único IP fez 31.062 tentativas, cerca de 6,6 por segundo, sempre com o usuário `root` e **uma senha diferente a cada vez** (31.060 senhas distintas). Em cada sessão aceita ele rodou só `echo -e "\x6F\x6B"`, que imprime "ok", e saiu. O padrão é compatível com um teste do tipo "este servidor aceita qualquer senha?", sinal de que é uma isca; os dados não provam essa intenção.
2. **Os robôs também testam a shell.** Roteiros fixos de comandos (`printf` com aspas e subshells, leitura de `/proc/self/stat`) rodaram 4.016 vezes cada, sempre iguais, o que aponta para uma mesma ferramenta repetindo o mesmo roteiro. Servem para distinguir uma shell de verdade de uma emulada. Quase todas as conexões (97%) se anunciaram como `SSH-2.0-Go`, um cliente escrito em Go, comum em ferramentas automatizadas.
3. **Reconhecimento do sistema é o primeiro passo.** O comando `uname -s -v -n -r -m` foi executado 46.576 vezes, e outras 1.948 pelo caminho `/bin/./uname`, uma variante que tenta escapar de filtros simples.
4. **Os arquivos enviados eram malware: mineradores e um bot de IRC.** Foram 111 envios de 4 arquivos diferentes, e o VirusTotal marca três como mineradores (36/64, 48/64 e 18/63 detecções em 20/11) e o quarto, enviado 2 vezes, como bot de IRC, um tipo de backdoor usado em botnets (40/61 em 25/11). O principal, `.16`, foi enviado 105 vezes e seguido de `chmod +x` em `/root/.16` (196 vezes) e em `/dev/shm/.16` (14). Uma segunda versão com o mesmo nome e conteúdo diferente tem menos detecções (18/63), o que sugere que os atacantes trocam a carga para escapar dos antivírus. Alguns roteiros tentaram ainda `sudo -S` com senhas chutadas.
5. **Comandos incomuns, repetidos 8 vezes cada,** aparecem como parte de um mesmo roteiro: procurar dados do Telegram Desktop (`~/.local/share/TelegramDesktop/tdata`), listar processos com "miner" no nome e um comando de roteadores MikroTik (`/ip cloud print`). Isso sugere que alguns roteiros buscam, além de minerar, dados e dispositivos de valor, mas a isca só registra os comandos, não o resultado.
6. **O servidor foi visto como ponte.** Dos 3.778 pedidos de túnel, 30% miravam a porta 25 (e-mail), o que sugere tentativa de usar servidores alheios para enviar spam; o restante se espalha pelo SSH (22), por portas web (443 e 80) e uma porta não padrão (2535).
7. **Uma curiosidade.** O usuário `claude` está entre os dez mais tentados (367 tentativas). Não investigamos o motivo.

## Mapeamento MITRE ATT&CK

Os comportamentos vistos na isca correspondem a sete técnicas do [MITRE ATT&CK](https://attack.mitre.org/), conferidas no site oficial em 23/11/2026. O mapeamento é interpretativo: a isca registra o que foi digitado, não a intenção de quem digitou.

| Comportamento observado | Técnica | Tática |
| --- | --- | --- |
| Tentativas de login com senhas de dicionário e, num robô, uma senha diferente a cada tentativa | [T1110.001 Password Guessing](https://attack.mitre.org/techniques/T1110/001/) | Credential Access |
| `uname -s -v -n -r -m` e leitura de `/proc` para descobrir o sistema | [T1082 System Information Discovery](https://attack.mitre.org/techniques/T1082/) | Discovery |
| Comandos que testam o comportamento da shell (`printf`, subshells, `/proc/self/stat`) para saber se ela é real | [T1497.001 Virtualization/Sandbox Evasion: System Checks](https://attack.mitre.org/techniques/T1497/001/) (aproximado) | Stealth, Discovery |
| Envio de arquivos (`.16`, `sshd`) à isca | [T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/) | Command and Control |
| `chmod +x` no arquivo enviado | [T1222.002 Linux and Mac Permissions](https://attack.mitre.org/techniques/T1222/) | Defense Impairment |
| Arquivos classificados pelo VirusTotal como mineradores de criptomoeda | [T1496.001 Compute Hijacking](https://attack.mitre.org/techniques/T1496/) (inferido pela classificação) | Impact |
| Pedidos de túnel (`direct-tcpip`) para usar o servidor como ponte | [T1090 Proxy](https://attack.mitre.org/techniques/T1090/001/) | Command and Control |

Duas ressalvas. O minerador não chegou a rodar, porque a shell é simulada: a técnica de sequestro de recursos é inferida a partir da natureza dos arquivos. E a técnica dos testes de shell é a mais próxima do que o ATT&CK descreve, não uma correspondência exata. Os nomes das táticas seguem a versão do site na data da consulta.

## Limitações

Os dados descrevem o que bateu **neste** servidor, nestas semanas. Não dão para generalizar para toda a internet.

- **Uma isca, um lugar, poucas semanas.** Outro provedor, outro país ou outro período podem mostrar outro perfil.
- **A isca aceita qualquer senha.** Por isso a taxa de login "aceito" não mede nada sobre os atacantes. Além disso, aceitar senhas aleatórias é um sinal conhecido de honeypot: um robô que testa isso e vai embora não chega a mostrar o que faria depois.
- **IP não é pessoa.** Um mesmo ator pode usar muitos IPs, e um IP pode ser um servidor invadido de uma vítima. Por isso o painel destaca IPs distintos, e não "quantos atacantes".
- **O país é o do registro do IP,** não o do invasor. VPNs e servidores alugados embaralham a origem.
- **Poucos robôs dominam as contagens.** Um único IP respondeu por boa parte das tentativas, o que distorce médias e totais; por isso os gráficos por dia, por hora e por usuário excluem esse IP.
- **A shell é simulada.** O que o invasor faz depois de entrar é limitado pelo que o Cowrie emula, e quem detecta a isca desiste cedo. A amostra tende a favorecer ferramentas automatizadas e menos sofisticadas.
- **Rótulos de antivírus são heurísticas.** A classificação dos arquivos vem do VirusTotal, sem análise dinâmica própria.
- **Primeiro e último dias incompletos,** porque a coleta começou e terminou no meio do dia.

## Recomendações defensivas

O que os dados mostram, em termos práticos, para quem administra um servidor SSH exposto:

1. **Desligue o login por senha e use só chaves SSH.** As senhas mais tentadas são as de dicionário (`123456`, `123`, `password`, `admin`, `root`); com chaves, esse tipo de tentativa não tem como funcionar.
2. **Proíba o login de root** e use um usuário comum com `sudo`.
3. **Limite quem alcança a porta de SSH:** firewall liberando só IPs conhecidos, VPN ou servidor de salto. Mudar a porta só reduz o ruído; não é proteção.
4. **Bloqueie tentativas repetidas** com uma ferramenta como o fail2ban, que corta IPs que erram demais.
5. **Desative o encaminhamento de portas** (`AllowTcpForwarding no`) onde não for necessário. A isca recebeu mais de 3 mil pedidos de túnel, tentativas de usar o servidor como ponte.
6. **Restrinja o tráfego de saída** do servidor, em especial e-mail (porta 25), para que uma invasão não vire fonte de spam.
7. **Monitore e atualize.** Os arquivos enviados à isca eram mineradores de criptomoeda e um bot de IRC; consumo anormal de CPU é um bom alarme de invasão.

## Reprodutibilidade e aprendizados

O tratamento dos dados é feito por três scripts em Python e um modelo de página, todos neste repositório. O log bruto e a lista de IPs não são publicados.

1. `analisa_cowrie.py` junta e agrega os logs, remove os acessos do autor e gera um resumo público sem IPs, mais listas privadas.
2. `paises.py` descobre o país de cada IP e acrescenta ao resumo só a contagem por país.
3. `gerar_dashboard.py` transforma o resumo no painel (um único arquivo HTML) e **para se achar algo parecido com um IP** no resumo.

O que o projeto ensinou:

- **Logs rodam por dia.** A primeira análise leu só o arquivo do dia e subestimou o volume; os arquivos diários precisam ser juntados antes de qualquer contagem.
- **O Docker publica portas por fora do UFW.** Regras de firewall do servidor não bastam para controlar o que fica exposto.
- **Um total simples engana.** Um único robô fez 35% das tentativas em 78 minutos. IPs distintos e gráficos sem o outlier contam a história real.
- **Privacidade se verifica, não se presume.** O primeiro filtro de IPs deixou passar o endereço do próprio servidor, embutido no nome de um cliente SSH. O problema foi achado ao revisar o resumo antes de publicar, e o filtro foi corrigido.
