# 🌐 Cybersecurity Tool

## 📖 Descrição
Uma ferramenta simples e eficaz para análise básica de vulnerabilidades em segurança cibernética com interface gráfica amigável e logs em tempo real.

## ⚙️ Funcionalidades
- 🔍 **Resolução Automática de IP:** Traduz automaticamente um domínio para o seu respectivo endereço IP
- 🛠️ **Escaneamento de Portas:** Analisa as portas mais comuns (1 a 1024) para identificar portas abertas
- 🛡️ **Verificação de Vulnerabilidades:**
  - 🗂️ **SQL Injection:** Testa se o website é vulnerável a injeção de SQL
  - ⚠️ **Cross-Site Scripting (XSS):** Verifica possíveis falhas de XSS em inputs do site
- 📊 **Relatório Completo:** Gera um relatório detalhado com os resultados das análises
- 📝 **Logs em Tempo Real:** Exibe o progresso de cada etapa diretamente na interface

## 🚀 Como Usar
1. Clone o repositório:
   ```bash
   git clone https://github.com/pablolazari/CybersecurityTool.git
   ```

2. Instale as dependências:
   ```bash
   pip install -r requirements.txt
   ```

3. Execute o programa:
   ```bash
   python security_scanner.py
   ```

## 🔧 Requisitos
- Python 3.7 ou superior
- Bibliotecas listadas em requirements.txt

## 📋 Notas Importantes
- Use esta ferramenta apenas em sistemas e websites que você tem permissão para testar
- Algumas funcionalidades podem ser bloqueadas por firewalls ou sistemas de segurança
- Recomenda-se o uso em ambiente de desenvolvimento/teste

## 👥 Contribuições
Contribuições são bem-vindas! Sinta-se à vontade para:
- Reportar bugs
- Sugerir novas funcionalidades
- Enviar pull requests

## 📄 Licença
Este projeto está sob a licença MIT. Veja o arquivo LICENSE para mais detalhes.