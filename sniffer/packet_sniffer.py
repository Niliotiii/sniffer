import argparse
import subprocess
import re
import sys
import signal
import time
import json
from datetime import datetime

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def signal_handler(sig, frame):
    print("\n" + Colors.BOLD + Colors.BLUE + "Captura finalizada pelo usuário." + Colors.ENDC)
    sys.exit(0)

def parse_args():
    parser = argparse.ArgumentParser(description="Sniffer baseado em tcpdump com visualização avançada de pacotes")
    parser.add_argument("-i", "--interface", help="Interface de rede para captura (ex: lo0, eth0, en0)")
    parser.add_argument("-p", "--port", type=int, help="Número da porta para filtrar")
    parser.add_argument("-t", "--type", choices=["tcp", "udp", "http", "all"], default="all", 
                        help="Tipo de pacote a ser capturado")
    parser.add_argument("-f", "--filter", help="Filtro BPF personalizado")
    parser.add_argument("-c", "--count", type=int, help="Número de pacotes a capturar")
    parser.add_argument("-s", "--size", type=int, default=0, help="Tamanho máximo do pacote a capturar (0=completo)")
    parser.add_argument("--no-payload", action="store_true", help="Não mostrar payload dos pacotes")
    parser.add_argument("-v", "--verbose", action="store_true", help="Mostrar informações detalhadas")
    return parser.parse_args()

def build_capture_filter(args):
    filters = []
    
    if args.type == "tcp":
        filters.append("tcp")
    elif args.type == "udp":
        filters.append("udp")
    elif args.type == "http":
        filters.append("tcp port 80 or tcp port 443 or tcp port 8080")
    
    if args.port:
        filters.append(f"port {args.port}")
    
    if args.filter:
        filters.append(f"({args.filter})")
    
    return " and ".join(filters) if filters else ""

def process_packet(packet_text):
    """Processa e formata um pacote capturado pelo tcpdump"""
    result = {}
    
    timestamp_match = re.search(r"^(\d{2}:\d{2}:\d{2}\.\d+)", packet_text)
    if timestamp_match:
        result["timestamp"] = timestamp_match.group(1)
    else:
        result["timestamp"] = datetime.now().strftime("%H:%M:%S.%f")

    ip_match = re.search(r"IP(?:v6)? ([\w\d\.-]+)\.(\d+) > ([\w\d\.-]+)\.(\d+)", packet_text)
    if ip_match:
        result["src_ip"] = ip_match.group(1)
        result["src_port"] = ip_match.group(2)
        result["dst_ip"] = ip_match.group(3)
        result["dst_port"] = ip_match.group(4)
        result["protocol"] = "TCP/UDP"
    else:
        alt_match = re.search(r"IP(?:v6)? ([^\s]+) > ([^\s]+)", packet_text)
        if alt_match:
            src_full = alt_match.group(1)
            dst_full = alt_match.group(2)
            
            if "." in src_full and "." in dst_full:
                src_parts = src_full.split(".")
                dst_parts = dst_full.split(".")
                
                result["src_ip"] = ".".join(src_parts[:-1])
                result["dst_ip"] = ".".join(dst_parts[:-1])
                result["src_port"] = src_parts[-1]
                result["dst_port"] = dst_parts[-1]
    
    if re.search(r"(GET|POST|PUT|DELETE|HEAD) .+ HTTP/[\d\.]+", packet_text, re.MULTILINE):
        result["protocol"] = "HTTP Request"
        http_match = re.search(r"(GET|POST|PUT|DELETE|HEAD) ([^\s]+) HTTP/[\d\.]+", packet_text)
        if http_match:
            result["http_method"] = http_match.group(1)
            result["http_path"] = http_match.group(2)
    elif re.search(r"HTTP/[\d\.]+ \d+ ", packet_text, re.MULTILINE):
        result["protocol"] = "HTTP Response"
        resp_match = re.search(r"HTTP/[\d\.]+ (\d+) (.+)", packet_text)
        if resp_match:
            result["http_status"] = resp_match.group(1)
            result["http_status_text"] = resp_match.group(2)
    
    json_match = re.search(r"({.+?})", packet_text)
    if json_match:
        try:
            json_str = json_match.group(1)
            json_data = json.loads(json_str)
            result["json_data"] = json_data
            
            if any(key in json_data for key in ["user", "username", "pass", "password", "token", "key"]):
                result["has_credentials"] = True
        except:
            pass
    
    form_match = re.findall(r"(username|user|password|pass|token)=([^&\s]+)", packet_text, re.IGNORECASE)
    if form_match:
        result["form_data"] = {k: v for k, v in form_match}
        result["has_credentials"] = True
    
    size_match = re.search(r"length (\d+)", packet_text)
    if size_match:
        result["size"] = int(size_match.group(1))
    
    return result

def format_packet_output(packet_info, show_payload=True, verbose=False):
    """Formata as informações do pacote para apresentação"""
    output = []
    
    header = f"{Colors.HEADER}{Colors.BOLD}[{packet_info['timestamp']}]{Colors.ENDC}"
    
    if "src_ip" in packet_info and "dst_ip" in packet_info:
        proto_info = f"{Colors.GREEN}{packet_info.get('protocol', 'TCP/UDP')}{Colors.ENDC}"
        conn_info = (f"{Colors.BLUE}{packet_info['src_ip']}:{packet_info['src_port']}{Colors.ENDC} → "
                    f"{Colors.BLUE}{packet_info['dst_ip']}:{packet_info['dst_port']}{Colors.ENDC}")
        header += f" {proto_info} {conn_info}"
    
    if "size" in packet_info:
        header += f" ({packet_info['size']} bytes)"
    
    output.append(header)
    
    output.append("─" * 80)
    
    if packet_info.get("protocol") == "HTTP Request" and "http_method" in packet_info:
        output.append(f"{Colors.BOLD}HTTP Request:{Colors.ENDC} {packet_info['http_method']} {packet_info['http_path']}")
    elif packet_info.get("protocol") == "HTTP Response" and "http_status" in packet_info:
        status_color = Colors.GREEN if packet_info["http_status"].startswith("2") else Colors.RED
        output.append(f"{Colors.BOLD}HTTP Response:{Colors.ENDC} {status_color}{packet_info['http_status']} {packet_info['http_status_text']}{Colors.ENDC}")
    
    if "form_data" in packet_info:
        output.append(f"{Colors.WARNING}{Colors.BOLD}Credenciais em Formulário:{Colors.ENDC}")
        for key, value in packet_info["form_data"].items():
            output.append(f"  {Colors.BOLD}{key}{Colors.ENDC}: {value}")
    
    if "json_data" in packet_info and verbose:
        output.append(f"{Colors.BOLD}Dados JSON:{Colors.ENDC}")
        json_str = json.dumps(packet_info["json_data"], indent=2)
        for line in json_str.split("\n"):
            if any(field in line.lower() for field in ["user", "pass", "token", "key", "secret"]):
                line = f"{Colors.WARNING}{line}{Colors.ENDC}"
            output.append(f"  {line}")
    
    if "payload" in packet_info and show_payload:
        output.append(f"{Colors.BOLD}Payload:{Colors.ENDC}")
        payload_lines = packet_info.get("payload", "").split("\n")
        for line in payload_lines[:20]:
            output.append(f"  {line}")
        if len(payload_lines) > 20:
            output.append(f"  ... {len(payload_lines)-20} linhas omitidas ...")
    
    output.append("═" * 80)
    return "\n".join(output)

def main():
    args = parse_args()
    signal.signal(signal.SIGINT, signal_handler)
    
    cmd = ["tcpdump", "-A", "-l"]
    
    if args.interface:
        cmd.extend(["-i", args.interface])
    
    if args.size:
        cmd.extend(["-s", str(args.size)])
    else:
        cmd.extend(["-s", "0"])
    
    if args.count:
        cmd.extend(["-c", str(args.count)])
    
    filter_expr = build_capture_filter(args)
    if filter_expr:
        cmd.append(filter_expr)
    
    print(f"{Colors.BOLD}{Colors.BLUE}Iniciando captura: {' '.join(cmd)}{Colors.ENDC}")
    print(f"{Colors.BOLD}Pressione Ctrl+C para finalizar{Colors.ENDC}")
    print("═" * 80)
    
    try:
        process = subprocess.Popen(
            cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True,
            bufsize=1
        )
        
        packet_buffer = []
        in_packet = False
        packets_processed = 0
        
        while True:
            line = process.stdout.readline()
            if not line:
                break
                
            if re.match(r"^\d{2}:", line):
                if packet_buffer:
                    try:
                        full_packet = "".join(packet_buffer)
                        packet_info = process_packet(full_packet)
                        packet_info["payload"] = full_packet
                        print(format_packet_output(packet_info, not args.no_payload, args.verbose))
                        packets_processed += 1
                    except Exception as e:
                        if args.verbose:
                            print(f"{Colors.RED}Erro ao processar pacote: {e}{Colors.ENDC}")
                
                packet_buffer = [line]
                in_packet = True
            elif in_packet:
                packet_buffer.append(line)
        
        if packet_buffer:
            try:
                full_packet = "".join(packet_buffer)
                packet_info = process_packet(full_packet)
                packet_info["payload"] = full_packet
                print(format_packet_output(packet_info, not args.no_payload, args.verbose))
                packets_processed += 1
            except Exception as e:
                if args.verbose:
                    print(f"{Colors.RED}Erro ao processar pacote: {e}{Colors.ENDC}")
    
    except Exception as e:
        print(f"{Colors.RED}Erro ao executar tcpdump: {e}{Colors.ENDC}")
    finally:
        print(f"{Colors.BLUE}Total de pacotes processados: {packets_processed}{Colors.ENDC}")

if __name__ == "__main__":
    main()