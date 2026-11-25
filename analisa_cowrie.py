#!/usr/bin/env python3
"""Resume um log do Cowrie (cowrie.json, um evento JSON por linha) em numeros agregados.

Gera, dentro da pasta de saida (padrao: ./saida):
  resumo_publico.json        numeros agregados, SEM IPs; alimenta o dashboard
  privado/ips.csv            IPs de origem com contagens          (NAO publicar)
  privado/destinos_tunel.csv destinos dos pedidos direct-tcpip     (NAO publicar)
  privado/downloads.csv      URLs de arquivos baixados, se houver  (NAO publicar)

Uso:
  python analisa_cowrie.py todos.json --meu-ip SEU.IP.DE.CASA

O IP de casa nao fica gravado no script: ele entra so pela linha de comando,
para que o script possa ser publicado no GitHub sem expor nada pessoal.
Use --meu-ip mais de uma vez se tiver mais de um IP a excluir.
"""

import argparse
import csv
import json
import os
import re
import statistics
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

URL_RE = re.compile(r"(?:https?|ftp)://\S+", re.I)
# (?<!\d) e (?!\d) em vez de \b: pega tambem IPs colados em "_" ou letras, como MGLNDD_1.2.3.4_22
IP_RE = re.compile(r"(?<!\d)\d{1,3}(?:\.\d{1,3}){3}(?!\d)(?::\d+)?")


def limpar(texto, limite=80):
    """Troca URLs e IPs por marcadores, junta espacos e corta o tamanho."""
    texto = URL_RE.sub("[url]", str(texto))
    texto = IP_RE.sub("[ip]", texto)
    texto = " ".join(texto.split())
    return texto[:limite]


def top(contador, n):
    return [{"valor": k, "total": v} for k, v in contador.most_common(n)]


def prefixo24(ip):
    partes = ip.split(".")
    if len(partes) == 4:
        return ".".join(partes[:3]) + ".x"
    return ip


def main():
    ap = argparse.ArgumentParser(description="Agrega um log do Cowrie.")
    ap.add_argument("log", help="arquivo cowrie.json (ou os logs juntados)")
    ap.add_argument("--meu-ip", action="append", required=True,
                    help="IP seu a excluir da analise (pode repetir)")
    ap.add_argument("--saida", default="saida", help="pasta de saida")
    args = ap.parse_args()
    meus = set(args.meu_ip)

    eventos = Counter()
    por_dia = Counter()
    aceitos_dia = Counter()
    ips_dia = defaultdict(set)
    por_hora = Counter()
    aceitos = recusados = chave_publica = 0
    credenciais, usuarios, senhas = Counter(), Counter(), Counter()
    comandos = Counter()
    comandos_total = 0
    uploads = Counter()
    downloads = Counter()
    downloads_url = Counter()
    tuneis_total = 0
    tuneis_porta, tuneis_destino = Counter(), Counter()
    clientes = Counter()
    sessoes, sessoes_com_cmd, duracoes = set(), set(), []
    ips = {}
    ip_dia = defaultdict(Counter)    # acessos por IP e por dia
    ip_hora = defaultdict(Counter)   # acessos por IP e por hora
    ip_senhas = defaultdict(set)     # senhas distintas por IP
    ip_usuarios = defaultdict(Counter)  # usuarios tentados por IP
    ip_cmds = defaultdict(Counter)   # comandos por IP
    linhas = invalidas = ignoradas = 0
    primeiro = ultimo = None

    with open(args.log, encoding="utf-8", errors="replace") as f:
        for linha in f:
            linhas += 1
            try:
                d = json.loads(linha)
            except ValueError:
                invalidas += 1
                continue
            if not isinstance(d, dict):
                invalidas += 1
                continue

            ip = d.get("src_ip")
            if ip in meus:
                ignoradas += 1
                continue

            ev = d.get("eventid", "")
            ts = d.get("timestamp") or ""
            eventos[ev] += 1
            if ts:
                primeiro = ts if primeiro is None or ts < primeiro else primeiro
                ultimo = ts if ultimo is None or ts > ultimo else ultimo

            st = None
            if ip:
                st = ips.setdefault(ip, {"acessos": 0, "comandos": 0, "uploads": 0,
                                         "tuneis": 0, "primeiro": ts, "ultimo": ts})
                if ts:
                    if not st["primeiro"] or ts < st["primeiro"]:
                        st["primeiro"] = ts
                    if ts > st["ultimo"]:
                        st["ultimo"] = ts

            sessao = d.get("session")

            if ev in ("cowrie.login.failed", "cowrie.login.success"):
                dia = ts[:10] or "desconhecido"
                hora = ts[11:13] or "??"
                por_dia[dia] += 1
                por_hora[hora] += 1
                if ip:
                    ips_dia[dia].add(ip)
                    ip_dia[ip][dia] += 1
                    ip_hora[ip][hora] += 1
                    st["acessos"] += 1
                if ev.endswith("success"):
                    aceitos += 1
                    aceitos_dia[dia] += 1
                else:
                    recusados += 1
                senha = d.get("password")
                usuario = d.get("username")
                if senha is None:
                    chave_publica += 1  # tentativa com chave publica, sem senha
                else:
                    u, s = limpar(usuario or "", 40), limpar(senha, 40)
                    credenciais[u + ":" + s] += 1
                    if ip:
                        ip_senhas[ip].add(s)
                        ip_usuarios[ip][u] += 1
                    usuarios[u] += 1
                    senhas[s] += 1

            elif ev == "cowrie.session.connect":
                if sessao:
                    sessoes.add(sessao)

            elif ev == "cowrie.session.closed":
                dur = d.get("duration")
                if isinstance(dur, (int, float)):
                    duracoes.append(float(dur))

            elif ev == "cowrie.command.input":
                comandos_total += 1
                cmd = limpar(d.get("input", ""))
                comandos[cmd] += 1
                if ip:
                    ip_cmds[ip][cmd] += 1
                if sessao:
                    sessoes_com_cmd.add(sessao)
                if st:
                    st["comandos"] += 1

            elif ev == "cowrie.session.file_upload":
                uploads[(limpar(d.get("filename", ""), 60), d.get("shasum", ""))] += 1
                if st:
                    st["uploads"] += 1

            elif ev == "cowrie.session.file_download":
                downloads[d.get("shasum", "")] += 1
                downloads_url[(d.get("url", ""), d.get("shasum", ""))] += 1

            elif ev == "cowrie.direct-tcpip.request":
                tuneis_total += 1
                porta = str(d.get("dst_port", "?"))
                tuneis_porta[porta] += 1
                tuneis_destino[(d.get("dst_ip", "?"), porta)] += 1
                if st:
                    st["tuneis"] += 1

            elif ev == "cowrie.client.version":
                clientes[limpar(d.get("version", ""), 50)] += 1

    if linhas == 0:
        sys.exit("O arquivo esta vazio.")

    total_logins = aceitos + recusados
    acessos_por_ip = sorted((v["acessos"] for v in ips.values()), reverse=True)
    soma_top5 = sum(acessos_por_ip[:5])
    pct = lambda a, b: round(100.0 * a / b, 1) if b else 0.0

    # IP mais ativo: o IP em si NUNCA vai para o resumo publico, so os numeros dele.
    topo = max(ips, key=lambda k: ips[k]["acessos"]) if ips else None
    if topo is not None and ips[topo]["acessos"] == 0:
        topo = None

    def dur_s(a, b):
        try:
            fa = datetime.fromisoformat(a.replace("Z", "+00:00"))
            fb = datetime.fromisoformat(b.replace("Z", "+00:00"))
            return max((fb - fa).total_seconds(), 0.0)
        except (ValueError, AttributeError):
            return None

    def linha_dia(dia):
        item = {"dia": dia, "acessos": por_dia[dia], "aceitos": aceitos_dia[dia],
                "ips_unicos": len(ips_dia[dia])}
        if topo is not None:
            do_topo = ip_dia[topo][dia]
            item["acessos_ip_mais_ativo"] = do_topo
            item["acessos_demais"] = por_dia[dia] - do_topo
        return item

    def linha_hora(h):
        item = {"hora": h, "acessos": por_hora[h]}
        if topo is not None:
            do_topo = ip_hora[topo][h]
            item["acessos_ip_mais_ativo"] = do_topo
            item["acessos_demais"] = por_hora[h] - do_topo
        return item

    ip_mais_ativo = None
    if topo is not None:
        st_top = ips[topo]
        cmd_top = ip_cmds[topo].most_common(1)
        ip_mais_ativo = {
            "acessos": st_top["acessos"],
            "pct_dos_acessos": pct(st_top["acessos"], total_logins),
            "acessos_demais": total_logins - st_top["acessos"],
            "ips_demais": len(ips) - 1,
            "comandos": st_top["comandos"],
            "senhas_distintas": len(ip_senhas[topo]),
            "comando_principal": cmd_top[0][0] if cmd_top else None,
            "comando_principal_total": cmd_top[0][1] if cmd_top else 0,
            "primeiro_visto_utc": st_top["primeiro"],
            "ultimo_visto_utc": st_top["ultimo"],
            "duracao_s": dur_s(st_top["primeiro"], st_top["ultimo"]),
        }

    resumo = {
        "gerado_em": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "periodo": {"primeiro_evento_utc": primeiro, "ultimo_evento_utc": ultimo},
        "qualidade": {"linhas_lidas": linhas, "linhas_invalidas": invalidas,
                      "eventos_ignorados_do_meu_ip": ignoradas},
        "acessos": {
            "total": total_logins,
            "aceitos": aceitos,
            "recusados": recusados,
            "pct_aceitos": pct(aceitos, total_logins),
            "tentativas_com_chave_publica": chave_publica,
            "ips_distintos": len(ips),
            "combinacoes_usuario_senha_distintas": len(credenciais),
            "pct_dos_5_ips_mais_ativos": pct(soma_top5, total_logins),
        },
        "ip_mais_ativo": ip_mais_ativo,
        "por_dia_utc": [linha_dia(dia) for dia in sorted(por_dia)],
        "por_hora_utc": [linha_hora(h) for h in sorted(por_hora)],
        "top_credenciais": top(credenciais, 20),
        "top_usuarios": top(usuarios, 10),
        "top_usuarios_sem_ip_mais_ativo": (
            top(usuarios - ip_usuarios[topo], 10) if topo is not None else None),
        "top_senhas": top(senhas, 15),
        "comandos": {"total": comandos_total, "distintos": len(comandos),
                     "top": top(comandos, 20)},
        "sessoes": {
            "total": len(sessoes),
            "com_comandos": len(sessoes_com_cmd),
            "duracao_mediana_s": round(statistics.median(duracoes), 1) if duracoes else None,
            "duracao_media_s": round(statistics.mean(duracoes), 1) if duracoes else None,
        },
        "arquivos_enviados": [
            {"nome": nome, "sha256": sha, "total": n}
            for (nome, sha), n in uploads.most_common()
        ],
        "arquivos_baixados": [{"sha256": sha, "total": n} for sha, n in downloads.most_common()],
        "tuneis": {"total": tuneis_total, "portas_de_destino": top(tuneis_porta, 10)},
        "clientes_ssh": top(clientes, 10),
        "eventos": top(eventos, 20),
    }

    os.makedirs(os.path.join(args.saida, "privado"), exist_ok=True)
    with open(os.path.join(args.saida, "resumo_publico.json"), "w", encoding="utf-8") as f:
        json.dump(resumo, f, ensure_ascii=False, indent=2)

    with open(os.path.join(args.saida, "privado", "ips.csv"), "w",
              newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["ip", "prefixo24", "acessos", "comandos", "uploads", "tuneis",
                    "primeiro_visto_utc", "ultimo_visto_utc"])
        for ip, v in sorted(ips.items(), key=lambda kv: -kv[1]["acessos"]):
            w.writerow([ip, prefixo24(ip), v["acessos"], v["comandos"], v["uploads"],
                        v["tuneis"], v["primeiro"], v["ultimo"]])

    with open(os.path.join(args.saida, "privado", "destinos_tunel.csv"), "w",
              newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["destino", "porta", "pedidos"])
        for (dst, porta), n in tuneis_destino.most_common():
            w.writerow([dst, porta, n])

    if downloads_url:
        with open(os.path.join(args.saida, "privado", "downloads.csv"), "w",
                  newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["url", "sha256", "vezes"])
            for (url, sha), n in downloads_url.most_common():
                w.writerow([url, sha, n])

    a = resumo["acessos"]
    print("Periodo (UTC): {} ate {}".format(primeiro, ultimo))
    print("Linhas lidas: {} (invalidas: {}; ignoradas por serem do meu IP: {})".format(
        linhas, invalidas, ignoradas))
    print("Acessos a isca: {} de {} IPs ({}% aceitos)".format(
        a["total"], a["ips_distintos"], a["pct_aceitos"]))
    print("Tentativas com chave publica (sem senha): {}".format(chave_publica))
    print("Combinacoes de usuario:senha distintas: {}".format(len(credenciais)))
    print("Os 5 IPs mais ativos respondem por {}% dos acessos".format(
        a["pct_dos_5_ips_mais_ativos"]))
    if ip_mais_ativo:
        print("IP mais ativo: {} acessos ({}% do total), {} senhas distintas".format(
            ip_mais_ativo["acessos"], ip_mais_ativo["pct_dos_acessos"],
            ip_mais_ativo["senhas_distintas"]))
    print("Comandos digitados: {} ({} distintos)".format(comandos_total, len(comandos)))
    print("Arquivos enviados a isca: {}".format(sum(uploads.values())))
    print("Pedidos de tunel: {}".format(tuneis_total))
    print("Por dia (UTC):")
    for item in resumo["por_dia_utc"]:
        print("  {}: {} acessos, {} IPs".format(item["dia"], item["acessos"], item["ips_unicos"]))
    print()
    print("Gerado: {}".format(os.path.join(args.saida, "resumo_publico.json")))
    print("ATENCAO: nao publique a pasta 'privado' nem o log original. "
          "Revise o resumo antes de divulgar qualquer coisa.")


if __name__ == "__main__":
    main()
