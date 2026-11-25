#!/usr/bin/env python3
"""Descobre o pais de origem de cada IP e grava SO as contagens por pais no resumo publico.

Uso (na pasta onde estao saida/ e os scripts), depois de rodar analisa_cowrie.py:
  python paises.py
  python gerar_dashboard.py

O que faz:
  1. le saida/privado/ips.csv (a lista de IPs, que fica so no seu PC);
  2. pergunta o pais de cada IP ao servico gratuito ip-api.com, em lotes de 100;
  3. guarda as respostas em saida/privado/paises_cache.csv (privado), para nao
     perguntar de novo o que ja sabe (na atualizacao final, so os IPs novos);
  4. acrescenta ao saida/resumo_publico.json apenas "pais -> quantos IPs".
     Nenhum IP vai para o resumo publico.

Sobre o servico: o plano gratuito so funciona por HTTP (sem criptografia), aceita
15 consultas por minuto e nao pode ser usado comercialmente. Os IPs enviados sao
os dos invasores que bateram na isca; o seu IP ja foi tirado pela analise.
O pais registrado de um IP pode nao ser onde a pessoa realmente esta (VPN, servidor alugado).
"""

import argparse
import csv
import json
import os
import sys
import time
import urllib.error
import urllib.request
from collections import Counter

API = "http://ip-api.com/batch?fields=status,country,query&lang=pt-BR"
LOTE = 100
DESCONHECIDO = "Desconhecido"

# O servico as vezes devolve nomes diferentes para o mesmo pais; aqui juntamos.
APELIDOS = {
    "EUA": "Estados Unidos",
    "Estados Unidos da América": "Estados Unidos",
    "United States": "Estados Unidos",
    "USA": "Estados Unidos",
    "Países Baixos": "Holanda",
    "República Federativa do Brasil": "Brasil",
    "Vietname": "Vietnã",
    "Mianmar (Birmânia)": "Mianmar",
    "Hong Kong": "Hong Kong, Região Admin. Especial da China",
}


class Limite(Exception):
    pass


def consultar(api, lote, timeout=30):
    """Envia um lote. Devolve (lista_de_respostas, restantes, ttl)."""
    req = urllib.request.Request(
        api, data=json.dumps(lote).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            corpo = json.loads(r.read().decode("utf-8"))
            return corpo, r.headers.get("X-Rl"), r.headers.get("X-Ttl")
    except urllib.error.HTTPError as e:
        if e.code == 429:
            raise Limite(e.headers.get("X-Ttl") or "60")
        raise


def inteiro(texto, padrao):
    try:
        return int(texto)
    except (TypeError, ValueError):
        return padrao


def ler_ips(caminho):
    with open(caminho, newline="", encoding="utf-8") as f:
        return [linha["ip"].strip() for linha in csv.DictReader(f) if linha.get("ip", "").strip()]


def ler_cache(caminho):
    cache = {}
    if os.path.exists(caminho):
        with open(caminho, newline="", encoding="utf-8") as f:
            for linha in csv.DictReader(f):
                if linha.get("ip"):
                    cache[linha["ip"]] = linha.get("pais") or DESCONHECIDO
    return cache


def main():
    ap = argparse.ArgumentParser(description="Conta IPs por pais.")
    ap.add_argument("--ips", default=os.path.join("saida", "privado", "ips.csv"))
    ap.add_argument("--resumo", default=os.path.join("saida", "resumo_publico.json"))
    ap.add_argument("--cache", default=os.path.join("saida", "privado", "paises_cache.csv"))
    ap.add_argument("--api", default=API)
    ap.add_argument("--pausa", type=float, default=5.0,
                    help="segundos entre lotes (5 = 12 por minuto, abaixo do limite de 15)")
    args = ap.parse_args()

    try:
        ips = ler_ips(args.ips)
    except (OSError, KeyError) as e:
        sys.exit("Nao consegui ler {}: {}\nRode antes o analisa_cowrie.py.".format(args.ips, e))
    try:
        with open(args.resumo, encoding="utf-8") as f:
            resumo = json.load(f)
    except (OSError, ValueError) as e:
        sys.exit("Nao consegui ler {}: {}".format(args.resumo, e))
    if not ips:
        sys.exit("A lista de IPs esta vazia.")

    unicos = list(dict.fromkeys(ips))
    cache = ler_cache(args.cache)
    pendentes = [ip for ip in unicos if ip not in cache]
    print("{} IPs na lista; {} ja conhecidos; {} para consultar.".format(
        len(unicos), len(unicos) - len(pendentes), len(pendentes)))

    novo_arquivo = not os.path.exists(args.cache)
    os.makedirs(os.path.dirname(args.cache) or ".", exist_ok=True)
    lotes = [pendentes[i:i + LOTE] for i in range(0, len(pendentes), LOTE)]
    with open(args.cache, "a", newline="", encoding="utf-8") as fc:
        w = csv.writer(fc)
        if novo_arquivo:
            w.writerow(["ip", "pais"])
        for n, lote in enumerate(lotes, 1):
            for tentativa in (1, 2):
                try:
                    resp, restantes, ttl = consultar(args.api, lote)
                    break
                except Limite as lim:
                    espera = inteiro(str(lim), 60) + 2
                    if tentativa == 2:
                        fc.flush()
                        sys.exit("O servico pediu para esperar de novo (limite de consultas). "
                                 "O progresso foi guardado. Rode o comando outra vez daqui a 1 hora.")
                    print("Limite do servico atingido; esperando {} s...".format(espera))
                    time.sleep(espera)
                except (urllib.error.URLError, OSError, ValueError) as e:
                    fc.flush()
                    sys.exit("Nao consegui falar com o servico ({}). Veja a internet e rode de novo; "
                             "o progresso foi guardado.".format(e))
            vistos = set()
            for item in resp if isinstance(resp, list) else []:
                ip = item.get("query")
                if not ip or ip in vistos:
                    continue
                vistos.add(ip)
                pais = item.get("country") if item.get("status") == "success" else None
                pais = (pais or DESCONHECIDO).strip() or DESCONHECIDO
                cache[ip] = pais
                w.writerow([ip, pais])
            fc.flush()
            print("Lote {}/{} feito ({} IPs).".format(n, len(lotes), len(vistos)))
            if n < len(lotes):
                if restantes is not None and inteiro(restantes, 1) <= 0:
                    time.sleep(inteiro(ttl, 60) + 1)
                else:
                    time.sleep(args.pausa)

    faltando = [ip for ip in unicos if ip not in cache]
    if faltando:
        print("Aviso: {} IPs ficaram sem resposta e contam como '{}'.".format(
            len(faltando), DESCONHECIDO))
    contagem = Counter(APELIDOS.get(cache.get(ip, DESCONHECIDO), cache.get(ip, DESCONHECIDO))
                       for ip in unicos)
    resumo["paises"] = [{"valor": p, "total": n} for p, n in contagem.most_common()]
    resumo["paises_distintos"] = len(contagem)
    resumo["paises_fonte"] = "ip-api.com"
    with open(args.resumo, "w", encoding="utf-8") as f:
        json.dump(resumo, f, ensure_ascii=False, indent=2)

    print()
    print("IPs por pais (top 10 de {} paises):".format(len(contagem)))
    for p, n in contagem.most_common(10):
        print("  {}: {}".format(p, n))
    print()
    print("Atualizado: {}  (so contagens, sem IPs)".format(args.resumo))
    print("Agora rode: python gerar_dashboard.py")


if __name__ == "__main__":
    main()
