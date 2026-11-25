#!/usr/bin/env python3
"""Gera o painel (index.html) a partir do resumo_publico.json.

Uso (na pasta onde estao os arquivos):
  python gerar_dashboard.py
  python gerar_dashboard.py saida/resumo_publico.json --autor "Seu Nome" --repo https://github.com/voce/honeypot

Le:     saida/resumo_publico.json  (gerado por analisa_cowrie.py)
        dashboard_modelo.html      (fica ao lado deste script)
Escreve: site/index.html            (abre com duplo clique e serve para o GitHub Pages)

Os dados ficam embutidos dentro do index.html, entao ele funciona offline.
Antes de escrever, o script confere que nao ha nenhum IP no resumo.
"""

import argparse
import json
import os
import re
import sys

# (?<!\d) e (?!\d) em vez de \b: pega tambem IPs colados em "_" ou letras, como MGLNDD_1.2.3.4_22
IP_RE = re.compile(r"(?<!\d)\d{1,3}(?:\.\d{1,3}){3}(?!\d)")
MARCADOR = "/*__DADOS__*/null"


def main():
    aqui = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description="Gera o painel HTML.")
    ap.add_argument("resumo", nargs="?", default=os.path.join("saida", "resumo_publico.json"))
    ap.add_argument("--modelo", default=os.path.join(aqui, "dashboard_modelo.html"))
    ap.add_argument("--saida", default=os.path.join("site", "index.html"))
    ap.add_argument("--vt", default="virustotal.json",
                    help="resultados do VirusTotal digitados por voce (opcional)")
    ap.add_argument("--autor", default="", help="nome no rodape (opcional)")
    ap.add_argument("--repo", default="", help="link https do repositorio (opcional)")
    args = ap.parse_args()

    try:
        with open(args.resumo, encoding="utf-8") as f:
            dados = json.load(f)
    except (OSError, ValueError) as e:
        sys.exit("Nao consegui ler {}: {}".format(args.resumo, e))
    try:
        with open(args.modelo, encoding="utf-8") as f:
            modelo = f.read()
    except OSError as e:
        sys.exit("Nao consegui ler o modelo {}: {}".format(args.modelo, e))
    if MARCADOR not in modelo:
        sys.exit("O modelo nao tem o marcador de dados; use o dashboard_modelo.html original.")
    if args.repo and not args.repo.startswith("https://"):
        sys.exit("--repo precisa comecar com https://")

    if os.path.exists(args.vt):
        try:
            with open(args.vt, encoding="utf-8") as f:
                vt = json.load(f)
            campos = ("sha256_prefixo", "placar", "rotulo", "consultado_em")
            dados["virustotal"] = [{k: str(item.get(k, "")) for k in campos}
                                   for item in vt if isinstance(item, dict)]
            print("Incluido: {} ({} arquivos)".format(args.vt, len(dados["virustotal"])))
        except (OSError, ValueError, AttributeError, TypeError) as e:
            sys.exit("Nao consegui ler {}: {}".format(args.vt, e))

    texto = json.dumps(dados, ensure_ascii=False)
    achados = sorted(set(IP_RE.findall(texto)))
    if achados:
        sys.exit("PARADO: encontrei algo parecido com IP no resumo ({}). "
                 "Nada foi gerado. Me mostre esse trecho antes de publicar.".format(
                     ", ".join(achados[:5])))

    dados["_meta"] = {"autor": args.autor, "repo": args.repo}
    carga = (json.dumps(dados, ensure_ascii=False)
             .replace("<", "\\u003c").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))
    html = modelo.replace(MARCADOR, carga)

    pasta = os.path.dirname(args.saida)
    if pasta:
        os.makedirs(pasta, exist_ok=True)
    with open(args.saida, "w", encoding="utf-8") as f:
        f.write(html)
    print("Gerado: {}  ({} KB)".format(args.saida, round(len(html.encode("utf-8")) / 1024)))
    print("Abra esse arquivo no navegador para conferir. Nenhum IP foi encontrado no resumo.")


if __name__ == "__main__":
    main()
