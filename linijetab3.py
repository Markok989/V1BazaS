"""
Elegantna tabela za brojanje linija Python koda
"""

import os
import sys
from datetime import datetime

class ElegantnaTabela:
    @staticmethod
    def kreiraj(zaglavlja, redovi, ukupni_red=None, title=None):
        """Kreira elegantnu tabelu sa ASCII okvirom."""
        
        # Dodaj # kolonu ako nije prisutna
        if zaglavlja[0] != "#":
            zaglavlja = ["#"] + zaglavlja
            for i, red in enumerate(redovi):
                redovi[i] = [str(i+1)] + red
            if ukupni_red:
                ukupni_red = [""] + ukupni_red
        
        # Izračunaj širine kolona
        col_widths = []
        for i in range(len(zaglavlja)):
            max_width = len(str(zaglavlja[i]))
            for red in redovi:
                if i < len(red):
                    max_width = max(max_width, len(str(red[i])))
            if ukupni_red and i < len(ukupni_red):
                max_width = max(max_width, len(str(ukupni_red[i])))
            col_widths.append(max_width + 2)  # +2 za padding
        
        # Funkcije za crtanje
        def top_border():
            return "┌" + "─".join("─" * w for w in col_widths) + "┐"
        
        def middle_border():
            return "├" + "─".join("─" * w for w in col_widths) + "┤"
        
        def bottom_border():
            return "└" + "─".join("─" * w for w in col_widths) + "┘"
        
        def row_cells(cells, is_header=False):
            row = "│"
            for i, cell in enumerate(cells):
                padding = col_widths[i] - len(str(cell)) - 1
                if is_header:
                    row += f" {str(cell).center(col_widths[i]-2)} │"
                else:
                    row += f" {str(cell).ljust(col_widths[i]-2)} │"
            return row
        
        # Kreiraj tabelu
        lines = []
        
        # Naslov (ako postoji)
        if title:
            total_width = sum(col_widths) + len(col_widths) - 1
            lines.append("╔" + "═" * (total_width - 2) + "╗")
            lines.append("║" + title.center(total_width - 2) + "║")
            lines.append("╠" + "═" * (total_width - 2) + "╣")
        
        # Gornji okvir
        lines.append(top_border())
        
        # Zaglavlje
        lines.append(row_cells(zaglavlja, is_header=True))
        lines.append(middle_border())
        
        # Redovi sa podacima
        for row in redovi:
            lines.append(row_cells(row))
        
        # Ukupni red (ako postoji)
        if ukupni_red:
            lines.append(middle_border())
            lines.append(row_cells(ukupni_red))
        
        # Donji okvir
        lines.append(bottom_border())
        
        return "\n".join(lines)

def skeniraj_python_fajlove(direktorijum):
    """Skenira i broji linije u Python fajlovima."""
    
    print(f"\n{'='*60}")
    print(f"SKENIRANJE: {os.path.abspath(direktorijum)}")
    print(f"{'='*60}")
    
    fajlovi = []
    ukupno_linija = 0
    
    for root, dirs, files in os.walk(direktorijum):
        # Ignoriši nepotrebne direktorijume
        ignore = ['venv', '.venv', 'env', '.git', '__pycache__', '.idea', 'node_modules']
        dirs[:] = [d for d in dirs if d not in ignore]
        
        for file in files:
            if file.endswith('.py'):
                putanja = os.path.join(root, file)
                rel_putanja = os.path.relpath(putanja, direktorijum)
                
                try:
                    with open(putanja, 'r', encoding='utf-8') as f:
                        linije = len(f.readlines())
                    
                    fajlovi.append({
                        'putanja': rel_putanja,
                        'ime': file,
                        'linije': linije
                    })
                    ukupno_linija += linije
                    
                    print(f"✓ {rel_putanja}: {linije} linija")
                    
                except Exception as e:
                    print(f"✗ {rel_putanja}: GREŠKA - {str(e)}")
    
    return fajlovi, ukupno_linija

def prikazi_rezultate(fajlovi, ukupno_linija, direktorijum):
    """Prikazuje rezultate u tabelarnom formatu."""
    
    if not fajlovi:
        print(f"\n{'!'*60}")
        print("NEMA PYTHON FAJLOVA U DIREKTORIJUMU!")
        print(f"{'!'*60}")
        return
    
    # Sortiraj fajlove po putanji
    fajlovi.sort(key=lambda x: x['putanja'].lower())
    
    # Pripremi podatke za tabelu
    tabela_podaci = []
    for fajl in fajlovi:
        putanja = fajl['putanja']
        if len(putanja) > 45:
            putanja = "..." + putanja[-42:]
        
        tabela_podaci.append([
            putanja,
            str(fajl['linije'])
        ])
    
    # Naslov tabele
    naslov = f"PYTHON FAJLOVI - {datetime.now().strftime('%d.%m.%Y')}"
    
    # Kreiraj tabelu
    tabela = ElegantnaTabela.kreiraj(
        zaglavlja=["FAJL", "LINIJA"],
        redovi=tabela_podaci,
        ukupni_red=[f"{len(fajlovi)} fajlova", str(ukupno_linija)],
        title=naslov
    )
    
    # Prikaži tabelu
    print(f"\n{tabela}")
    
    # Statistika
    print(f"\n{'─'*60}")
    print("📈 STATISTIKA:")
    print(f"{'─'*60}")
    
    if fajlovi:
        avg = ukupno_linija / len(fajlovi)
        max_f = max(fajlovi, key=lambda x: x['linije'])
        min_f = min(fajlovi, key=lambda x: x['linije'])
        
        print(f"• Direktorijum:   {os.path.abspath(direktorijum)}")
        print(f"• Ukupno fajlova: {len(fajlovi)}")
        print(f"• Ukupno linija:  {ukupno_linija}")
        print(f"• Prosečno:       {avg:.1f} linija/fajl")
        print(f"• Najveći:        {max_f['ime']} ({max_f['linije']} linija)")
        print(f"• Najmanji:       {min_f['ime']} ({min_f['linije']} linija)")

def main():
    """Glavna funkcija."""
    
    # Proveri argumente
    dir_path = "."
    
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        if os.path.isdir(arg):
            dir_path = arg
        elif arg in ['-h', '--help']:
            print(f"\n{'='*60}")
            print("PYTHON LINE COUNTER - POMOĆ")
            print(f"{'='*60}")
            print("\nUpotreba: python linije_tabela.py [direktorijum]")
            print("\nPrimeri:")
            print("  python linije_tabela.py              # Trenutni direktorijum")
            print("  python linije_tabela.py C:\\projekti  # Određeni direktorijum")
            print("  python linije_tabela.py -h           # Prikaži pomoć")
            return
        else:
            print(f"\n❌ Greška: Direktorijum '{arg}' ne postoji!")
            return
    
    try:
        # Skeniraj fajlove
        fajlovi, ukupno = skeniraj_python_fajlove(dir_path)
        
        # Prikaži rezultate
        prikazi_rezultate(fajlovi, ukupno, dir_path)
        
        print(f"\n{'='*60}")
        print("✅ BROJANJE ZAVRŠENO USPEŠNO!")
        print(f"{'='*60}")
        
    except KeyboardInterrupt:
        print(f"\n\n⏹️  Prekinuto od strane korisnika")
    except Exception as e:
        print(f"\n❌ Greška: {e}")

if __name__ == "__main__":
    main()