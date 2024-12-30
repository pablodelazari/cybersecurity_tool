import socket
import requests
from bs4 import BeautifulSoup
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
from tkinter.ttk import Progressbar
import threading
import re
import json
import concurrent.futures
from advanced_scanner import AdvancedScanner
import os
from datetime import datetime
from utils import *

class SecurityScanner:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Ferramenta de Análise de Segurança")
        self.window.geometry("800x600")
        
        self.setup_ui()
        self.advanced_scanner = AdvancedScanner()
        
    def setup_ui(self):
        # Frame principal
        main_frame = ttk.Frame(self.window, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # URL entry
        ttk.Label(main_frame, text="URL ou IP do alvo:").grid(row=0, column=0, sticky=tk.W)
        self.url_entry = ttk.Entry(main_frame, width=50)
        self.url_entry.grid(row=0, column=1, padx=5, pady=5)
        
        # Opções de scan
        options_frame = ttk.LabelFrame(main_frame, text="Opções de Scan", padding="5")
        options_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        self.port_scan_var = tk.BooleanVar(value=True)
        self.vuln_scan_var = tk.BooleanVar(value=True)
        self.ssl_scan_var = tk.BooleanVar(value=True)
        self.subdomain_scan_var = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(options_frame, text="Scanner de Portas", variable=self.port_scan_var).grid(row=0, column=0)
        ttk.Checkbutton(options_frame, text="Verificação de Vulnerabilidades", variable=self.vuln_scan_var).grid(row=0, column=1)
        ttk.Checkbutton(options_frame, text="Análise SSL", variable=self.ssl_scan_var).grid(row=0, column=2)
        ttk.Checkbutton(options_frame, text="Varredura de Subdomínios", variable=self.subdomain_scan_var).grid(row=0, column=3)
        
        # Botões
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.grid(row=2, column=0, columnspan=2, pady=10)
        
        ttk.Button(buttons_frame, text="Iniciar Scan", command=self.start_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Limpar Log", command=self.clear_log).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Salvar Relatório", command=self.save_report).pack(side=tk.LEFT, padx=5)
        
        # Barra de progresso
        self.progress = ttk.Progressbar(main_frame, length=300, mode='determinate')
        self.progress.grid(row=3, column=0, columnspan=2, pady=5)
        
        # Area de log
        self.log = scrolledtext.ScrolledText(main_frame, height=20, width=80)
        self.log.grid(row=4, column=0, columnspan=2, pady=5)
        
        # Configurando tags para colorir o texto
        self.log.tag_configure('error', foreground='red')
        self.log.tag_configure('success', foreground='green')
        self.log.tag_configure('warning', foreground='orange')
        self.log.tag_configure('info', foreground='blue')
        
    def clear_log(self):
        """Limpa a área de log."""
        self.log.delete(1.0, tk.END)
        self.progress['value'] = 0
        
    def save_report(self):
        """Salva o conteúdo atual do log em um arquivo."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_dir = "reports"
        
        if not os.path.exists(report_dir):
            os.makedirs(report_dir)
            
        filename = f"security_report_{timestamp}.txt"
        filepath = os.path.join(report_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(self.log.get(1.0, tk.END))
        
        messagebox.showinfo("Sucesso", f"Relatório salvo em: {filepath}")
        
    def start_scan(self):
        """Inicia o processo de scan."""
        def scan_thread():
            target = self.url_entry.get().strip()
            
            # Validação inicial
            domain_info = get_domain_info(target)
            if "error" in domain_info:
                self.log.insert(tk.END, f"Erro: {domain_info['error']}\n", 'error')
                return
                
            self.log.delete(1.0, tk.END)
            self.log.insert(tk.END, f"Iniciando scan em: {target}\n", 'info')
            
            results = {
                "target": target,
                "timestamp": datetime.now().isoformat(),
                "domain_info": domain_info,
                "scan_options": {
                    "port_scan": self.port_scan_var.get(),
                    "vulnerability_scan": self.vuln_scan_var.get(),
                    "ssl_scan": self.ssl_scan_var.get(),
                    "subdomain_scan": self.subdomain_scan_var.get()
                }
            }
            
            try:
                # Scanner de Portas
                if self.port_scan_var.get():
                    self.log.insert(tk.END, "Iniciando scanner de portas...\n", 'info')
                    ports = range(1, 1025)
                    open_ports = {}
                    
                    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                        future_to_port = {
                            executor.submit(self.check_port, domain_info["ip"], port): port 
                            for port in ports
                        }
                        total = len(future_to_port)
                        completed = 0
                        
                        for future in concurrent.futures.as_completed(future_to_port):
                            port = future_to_port[future]
                            completed += 1
                            self.progress['value'] = (completed / total) * 100
                            
                            try:
                                if future.result():
                                    service = format_port_description(port)
                                    open_ports[port] = service
                                    self.log.insert(tk.END, f"Porta {port} ({service}) está aberta\n", 'success')
                            except Exception as e:
                                self.log.insert(tk.END, f"Erro ao verificar porta {port}: {str(e)}\n", 'error')
                                
                    results["open_ports"] = open_ports
                    
                # Verificações Avançadas
                if any([self.vuln_scan_var.get(), self.ssl_scan_var.get(), self.subdomain_scan_var.get()]):
                    self.log.insert(tk.END, "Iniciando verificações avançadas...\n", 'info')
                    advanced_results = self.advanced_scanner.run_full_scan(target)
                    results.update(advanced_results)
                    
                    if "ssl_security" in advanced_results:
                        ssl_info = advanced_results["ssl_security"]
                        if ssl_info["status"] == "secure":
                            self.log.insert(tk.END, "Certificado SSL válido encontrado\n", 'success')
                        else:
                            self.log.insert(tk.END, f"Problema com SSL: {ssl_info['message']}\n", 'warning')
                            
                    if "directory_traversal" in advanced_results:
                        dt_info = advanced_results["directory_traversal"]
                        if dt_info["vulnerable"]:
                            self.log.insert(tk.END, "Vulnerabilidade de Directory Traversal encontrada!\n", 'error')
                            
                    if "file_inclusion" in advanced_results:
                        fi_info = advanced_results["file_inclusion"]
                        if fi_info["lfi_vulnerable"] or fi_info["rfi_vulnerable"]:
                            self.log.insert(tk.END, "Vulnerabilidade de File Inclusion encontrada!\n", 'error')
                            
                # Gerar relatório final
                self.generate_report(results)
                self.log.insert(tk.END, "Scan concluído com sucesso!\n", 'success')
                
            except Exception as e:
                error_report = create_error_report(e, "scan_execution")
                self.log.insert(tk.END, f"Erro durante o scan: {error_report['error_message']}\n", 'error')
                for suggestion in error_report['suggestions']:
                    self.log.insert(tk.END, f"Sugestão: {suggestion}\n", 'info')
                    
            finally:
                self.progress['value'] = 0
                
        threading.Thread(target=scan_thread).start()
        
    def check_port(self, target, port):
        """Verifica se uma porta específica está aberta."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                result = s.connect_ex((target, port))
                return result == 0
        except:
            return False
            
    def generate_report(self, results):
        """Gera um relatório detalhado do scan."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_dir = "reports"
        if not os.path.exists(report_dir):
            os.makedirs(report_dir)
            
        report_path = os.path.join(report_dir, f"security_report_{timestamp}.json")
        
        with open(report_path, "w") as f:
            json.dump(results, f, indent=4)
            
        self.log.insert(tk.END, f"Relatório detalhado salvo em: {report_path}\n", 'success')
        
    def run(self):
        """Inicia a aplicação."""
        self.window.mainloop()

if __name__ == "__main__":
    tool = SecurityScanner()
    tool.run()