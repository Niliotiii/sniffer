# Visão Geral do Projeto

Este projeto implementa um **sniffer de rede** com duas interfaces:

- **Interface Web**: Uma aplicação web de login para testes.
- **Linha de Comando**: Um script Python para captura e análise rápida de pacotes diretamente no terminal.

O sniffer foi projetado especialmente para detectar e analisar **tráfego HTTP**, destacando informações importantes como credenciais em formulários e dados JSON.

---

# Pré-requisitos e Instalação

## Requisitos de Sistema

- Python 3.6 ou superior  
- `tcpdump` instalado no sistema operacional  
- Privilégios de administrador (sudo) para captura de pacotes

## Instalação

1. Clone o repositório:
   ```bash
   git clone https://github.com/Niliotiii/sniffer
   cd sniffer
   ```

2. Instale o `tcpdump` (se necessário):

   - **macOS**:
     ```bash
     brew install tcpdump
     ```

   - **Linux (Ubuntu/Debian)**:
     ```bash
     sudo apt-get install tcpdump
     ```

3. Configure um ambiente virtual Python (recomendado):
   ```bash
   cd sniffer
   python3 -m venv venv
   source venv/bin/activate
   ```

4. Dê permissão de execução ao script principal:
   ```bash
   chmod +x packet_sniffer.py
   ```

---

# Como Executar o Sniffer

## Interface de Linha de Comando

O script `packet_sniffer.py` oferece diversas opções para personalizar a captura:

```bash
sudo ./packet_sniffer.py -i [interface] -t [tipo] -p [porta]
```

### Parâmetros Principais

- `-i`, `--interface`: Interface de rede (ex: `lo0`, `eth0`)
- `-t`, `--type`: Tipo de pacote (`tcp`, `udp`, `http`, `all`)
- `-p`, `--port`: Número da porta para filtrar
- `-f`, `--filter`: Filtro BPF personalizado
- `-v`, `--verbose`: Mostrar informações detalhadas
- `--no-payload`: Não exibir o payload dos pacotes

### Exemplo

Capturar tráfego da porta 3000 na interface loopback:
```bash
sudo ./packet_sniffer.py -i lo0 -p 3000
```

---

# Como Iniciar a Página de Login

O projeto inclui um servidor de login para testes.

1. Navegue até a pasta do servidor de login:
   ```bash
   cd login-test
   ```

2. Instale as dependências:
   ```bash
   npm install
   ```

3. Inicie o servidor:
   ```bash
   node server.js
   ```

---

> ⚠️ **Nota de Segurança:**  
> Este sniffer foi desenvolvido **exclusivamente para fins educacionais e testes em ambientes controlados**.  
> **Utilize-o apenas em redes e sistemas nos quais você tenha permissão para monitorar.**
