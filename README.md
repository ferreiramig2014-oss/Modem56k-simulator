Sistema Operacional

Windows apenas — o modem56k.py usa winsound que é exclusivo do Windows. Testado no Windows 10/11.

Python

3.8 ou superior (usa f-strings, walrus operator não, mas threading e socket modernos)

Dependências Python
pip install pyserial
Só isso. winsound, socket, threading, struct, hashlib são todos stdlib.
Dependências externas

com0com — cria o par de portas virtuais COM10 ↔ COM11. Download: https://com0com.sourceforge.net/
VirtualModem56k.inf — driver INF que faz o Windows enxergar a COM10 como "Virtual Fax/Modem 56kbps" (incluído no repositório)

Arquivos necessários na mesma pasta
modem56k.py
ppp_server.py
nat.py
dial-up-sound_1.wav   ← opcional, mas recomendado
VirtualModem56k.inf

Permissões: 

Python precisa rodar com permissão de acesso à porta serial (normalmente sem admin)
A instalação do install.bat e do com0com precisam de admin (só uma vez)
Configuração do Windows DUN
Protocolo IPv4 marcado, IPv6 desmarcado
"Usar gateway padrão na rede remota" desmarcado (para o NAT funcionar)
Usuário: discador / Senha: 1234 (configurável em config.ini)

Sobre vulnerabilidades: 
Sem risco real (por ser local): O PAP manda usuário e senha em texto claro pela porta serial, mas como é uma porta virtual do com0com dentro do próprio PC, ninguém de fora intercepta. Isso só viraria problema se você expusesse a COM10 via rede (ex: com2tcp), que não é o caso.
Riscos que existem independente da sua mudança:
O NAT não filtra destinos — qualquer IP/porta é alcançável pelo cliente PPP. Se alguém conectar, consegue acessar qualquer site ou serviço. Com MAX_SESSOES = 1 e a proteção de brute-force, isso já está bem contido, mas vale saber.
As credenciais ficam em hash SHA-256 no código (ppp_server.py), o que é bom, mas o código é seu e fica em texto no disco — então a segurança real depende de quem tem acesso à máquina.
Resumo: para uso local (você testando o discador antigo), o risco é mínimo. Não expõe nada para a internet e o atacante precisaria já estar dentro do seu PC pra fazer algo.
