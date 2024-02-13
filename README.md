Verktygslåda för CTF (Capture The Flag)
Introduktion
toolbox.CTF är en samling av verktyg utformade för att hjälpa till i Capture The Flag (CTF)-tävlingar och allmänna cybersäkerhetspraktiker. Den här verktygslådan innehåller olika skript och verktyg för uppgifter som skanning, brute-force-attacker och analys av filer för skadligt innehåll med hjälp av VirusTotal's API.

Medföljande verktyg
VirusTotal_API.py
Detta skript gör det möjligt för användare att söka efter filhashar mot VirusTotals databas för att identifiera potentiellt skadliga filer. Det kräver en API-nyckel från VirusTotal för att fungera.

bruteforce.py
Ett verktyg för att försöka utföra brute-force-attacker på olika tjänster. Det kan anpassas för att rikta in sig på olika portar och tjänster efter behov.

nmap_scanner.py
En Python-omslag för nmap, vilket underlättar automatiserad skanning och rapportering. Det kan användas för att utföra omfattande skanningar av målnätverk eller system.

nmap_scan_report.docx
En mall för rapportdokument för att presentera resultat från nmap_scanner.py-skanningar på ett lättläst format.

Användning
Inställning
Klona repositatoriet till din lokala maskin.
Se till att du har Python installerat.
Installera eventuella beroenden som krävs av de enskilda skripten, vanligtvis via pip install -r requirements.txt.
bash
Copy code
git clone https://github.com/mangeeriiksson/toolbox.CTF
cd toolbox-ctf
pip install -r requirements.txt
Körning av skript
Varje skript kan köras från kommandoraden. Till exempel, för att använda VirusTotal_API.py, skulle du köra:

bash
Copy code
python VirusTotal_API.py <fil-hash>
