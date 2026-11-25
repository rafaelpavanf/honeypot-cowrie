# Honeypot SSH com Cowrie

Um servidor SSH de mentira (honeypot) ficou exposto na internet por 17 dias (9 a 25 de novembro de 2026) e registrou quem tentou entrar, com quais senhas e o que fez depois.

**Painel interativo:** https://rafaelpavanf.github.io/honeypot-cowrie/

## Resultados

- 88.230 tentativas de login, vindas de 2.336 IPs distintos em 117 países
- 233.277 comandos digitados na shell falsa
- 111 envios de arquivos (4 arquivos diferentes): mineradores de criptomoeda e um bot de IRC, segundo o VirusTotal
- 3.778 pedidos para usar o servidor como ponte (túnel)
- Um único IP fez 35% das tentativas em 78 minutos, testando uma senha diferente a cada vez

O relatório completo, com metodologia, mapeamento MITRE ATT&CK, limitações e recomendações, está em [RELATORIO.md](RELATORIO.md).

## Como foi feito

- Cowrie (imagem oficial) em Docker numa VPS dedicada só a isso, sem dados reais
- Administração em outra porta, somente com chave SSH, atrás de firewall
- Análise em Python; painel em um único arquivo HTML

## Scripts

| Arquivo | O que faz |
|---|---|
| `analisa_cowrie.py` | Junta e agrega os logs, remove os acessos do autor e gera um resumo público **sem IPs** |
| `paises.py` | Descobre o país de cada IP (ip-api.com) e acrescenta só a contagem por país |
| `gerar_dashboard.py` | Gera o painel a partir do resumo e **para se achar algo parecido com um IP** |
| `dashboard_modelo.html` | Modelo da página do painel |
| `virustotal.json` | Placares do VirusTotal, consultados só pelo hash, digitados à mão |

Uso, na pasta com o log (`todos.json`):

```
python analisa_cowrie.py todos.json --meu-ip SEU_IP
python paises.py
python gerar_dashboard.py --autor "Seu Nome"
```

## Privacidade e ética

- Nenhum endereço IP é publicado: o painel e o relatório mostram só contagens.
- O log bruto e a lista de IPs ficam fora do repositório.
- Nenhum arquivo enviado pelos invasores foi executado ou publicado; só os hashes foram consultados.
- Nenhuma ação foi tomada contra os atacantes.

## Limitações

Os dados descrevem o que bateu neste servidor, nestas semanas. A isca aceita qualquer senha de propósito, IP não é pessoa, e o país é o do registro do IP. Detalhes no relatório.

Projeto de Rafael Pavan, estudante de Segurança da Informação (Unisinos).
