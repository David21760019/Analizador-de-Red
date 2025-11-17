import tkinter as tk
from tkinter import ttk, messagebox
import ipaddress
import subprocess
import concurrent.futures
import threading
import re
import time
import socket
import sys

# ---------------------------
# Helpers: parse user range
# ---------------------------
def parse_input_to_ips(text):
    text = text.strip()
    if not text:
        return []
    parts = [p.strip() for p in text.split(",") if p.strip()]
    ips = []
    for p in parts:
        if "/" in p:
            try:
                net = ipaddress.ip_network(p, strict=False)
                ips.extend([str(ip) for ip in net.hosts()])
            except Exception as e:
                raise ValueError(f"CIDR inválido: {p}") from e
        elif "-" in p:
            try:
                start, end = p.split("-", 1)
                start = ipaddress.IPv4Address(start.strip())
                end = ipaddress.IPv4Address(end.strip())
                if int(end) < int(start):
                    raise ValueError("Rango inválido (end < start)")
                cur = int(start)
                while cur <= int(end):
                    ips.append(str(ipaddress.IPv4Address(cur)))
                    cur += 1
            except Exception as e:
                raise ValueError(f"Rango inválido: {p}") from e
        else:
            try:
                _ = ipaddress.IPv4Address(p)
                ips.append(p)
            except Exception as e:
                raise ValueError(f"IP inválida: {p}") from e

    seen = set()
    out = []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out

# ---------------------------
# Ping (Windows)
# ---------------------------
def ping_ip(ip, timeout_ms):
    cmd = f'ping -n 1 -w {int(timeout_ms)} {ip}'
    try:
        res = subprocess.run(cmd, shell=True,
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
        return res.returncode == 0
    except:
        return False

# ---------------------------
# Leer ARP
# ---------------------------
def read_arp_table():
    try:
        output = subprocess.check_output("arp -a", shell=True).decode("latin-1", errors="ignore")
    except:
        return {}

    pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F][0-9a-fA-F][-:](?:[0-9a-fA-F]{2}[-:]){4}[0-9a-fA-F]{2})")
    table = {}
    for m in pattern.finditer(output):
        ip = m.group(1)
        mac = m.group(2).replace("-", ":").lower()
        table[ip] = mac
    return table




def resolve_hostnames(ips, max_workers=30):
    def _resolve(ip):
        try:
            return (ip, socket.gethostbyaddr(ip)[0])
        except:
            return (ip, "")
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        for ip, name in ex.map(_resolve, ips):
            results[ip] = name or ""
    return results




def scan_range(ips, timeout_ms, workers, log_callback, progress_callback):
    total = len(ips)
    if total == 0:
        return []

    log_callback(f"Escaneando {total} IPs…")

    responsive = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(ping_ip, ip, timeout_ms): ip for ip in ips}
        done = 0
        for fut in concurrent.futures.as_completed(futures):
            ip = futures[fut]
            try:
                alive = fut.result()
            except:
                alive = False
            if alive:
                responsive.add(ip)
            done += 1
            progress_callback(done, total)

    log_callback(f"Pings completados. {len(responsive)} respondieron.")

    time.sleep(0.2)
    arp = read_arp_table()
    log_callback(f"ARP detectados: {len(arp)}")

    ips_to_resolve = [ip for ip in ips if ip in arp or ip in responsive]

    hostnames = resolve_hostnames(
        ips_to_resolve,
        max_workers=min(40, max(4, workers // 2))
    )

    results = []
    for ip in ips_to_resolve:
        mac = arp.get(ip, "")
        hostname = hostnames.get(ip, "")
        results.append({"ip": ip, "mac": mac, "hostname": hostname, "icmp": (ip in responsive)})

    return results

# ---------------------------
# GUI
# ---------------------------
class IPScannerGUI:
    def __init__(self, root):
        self.root = root
        root.title("Escáner de Red")
        root.geometry("900x600")

        frm = ttk.Frame(root, padding=10)
        frm.pack(fill="both", expand=True)

        ttk.Label(frm, text="Red (CIDR, rango o lista):").grid(row=0, column=0, sticky="w")
        self.range_entry = ttk.Entry(frm, width=60)
        self.range_entry.grid(row=0, column=1, sticky="w")
        self.range_entry.insert(0, "192.168.1.0/24")

        ttk.Button(frm, text="Iniciar escaneo", command=self.on_scan).grid(row=0, column=2)

        self.timeout_ms = 1200
        self.workers = 80

        self.progress = ttk.Progressbar(frm, orient="horizontal", length=800, mode="determinate")
        self.progress.grid(row=1, column=0, columnspan=3, pady=5)

        self.log_text = tk.Text(frm, height=8)
        self.log_text.grid(row=2, column=0, columnspan=3, sticky="nsew")

        columns = ("ip", "mac", "hostname", "icmp")
        self.tree = ttk.Treeview(frm, columns=columns, show="headings", height=18)
        for c in columns:
            self.tree.heading(c, text=c.upper())
            self.tree.column(c, width=200)
        self.tree.grid(row=3, column=0, columnspan=3, sticky="nsew")

        # COLORES
        self.tree.tag_configure("online", background="#b6fcb6")   # verde
        self.tree.tag_configure("offline", background="#d9d9d9")  # gris

        self.previous_devices = {}    # Solo guarda los que respondieron ICMP

        frm.rowconfigure(3, weight=1)
        frm.columnconfigure(1, weight=1)

    def log(self, text):
        ts = time.strftime("%H:%M:%S")
        self.log_text.insert("end", f"[{ts}] {text}\n")
        self.log_text.see("end")

    def set_progress(self, value, maximum):
        self.progress["maximum"] = maximum
        self.progress["value"] = value

    def on_scan(self):
        txt = self.range_entry.get().strip()
        if not txt:
            messagebox.showerror("Error", "Introduce una red válida.")
            return

        try:
            ips = parse_input_to_ips(txt)
        except Exception as e:
            messagebox.showerror("Error", str(e))
            return

        self.tree.delete(*self.tree.get_children())
        self.log_text.delete("1.0", "end")
        self.progress["value"] = 0

        t = threading.Thread(target=self._run_scan_thread, args=(ips,), daemon=True)
        t.start()

    def _run_scan_thread(self, ips):
        total = len(ips)
        self.log(f"Iniciando escaneo de {total} IPs…")

        def progress_cb(done, total_inner):
            self.root.after(0, lambda: self.set_progress(done, total_inner))

        results = scan_range(
            ips,
            self.timeout_ms,
            self.workers,
            log_callback=lambda s: self.root.after(0, lambda s=s: self.log(s)),
            progress_callback=progress_cb
        )

        def show_results():
            first_scan = (len(self.previous_devices) == 0)

            self.tree.delete(*self.tree.get_children())

            for row in results:
                ip = row["ip"]

                # ❗ PRIMER ESCANEO → SOLO mostrar activos
                if first_scan and not row["icmp"]:
                    continue

                mac = row["mac"]
                host = row["hostname"]
                icmp = "yes" if row["icmp"] else "no"

                # colores:
                if row["icmp"]:
                    tag = "online"
                else:
                    tag = "offline" if ip in self.previous_devices else ""

                self.tree.insert("", "end", values=(ip, mac, host, icmp), tags=(tag,))

            # guardar solo los activos
            self.previous_devices = {row["ip"]: True for row in results if row["icmp"]}

            self.log("Escaneo finalizado.")
            self.set_progress(0, 1)

        self.root.after(0, show_results)


def main():
    root = tk.Tk()
    ttk.Style().theme_use('clam')
    IPScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
