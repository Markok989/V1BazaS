"""
Modern Python Line Counter sa savršeno poravnatim tabelama za PowerShell
"""

import os
import sys
from datetime import datetime
from pathlib import Path

class Color:
    """ANSI kodovi za boje u PowerShell/CMD"""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    RED = "\033[91m"
    GRAY = "\033[90m"
    WHITE = "\033[97m"

class PerfectTable:
    """Klasa za kreiranje savršeno poravnatih tabela"""
    
    @staticmethod
    def create_table(headers, data, totals=None, title=None, max_file_width=50):
        """
        Kreira perfektno poravnatu tabelu
        
        Args:
            headers: Lista naziva kolona
            data: Lista listi sa podacima
            totals: Podaci za ukupni red
            title: Naslov tabele
            max_file_width: Maksimalna širina za kolonu fajlova
        """
        # Dodaj redne brojeve ako već nisu prisutni
        if headers[0] != "#":
            headers = ["#"] + list(headers)
            for i, row in enumerate(data):
                data[i] = [str(i+1)] + list(row)
            if totals:
                totals = [""] + list(totals)
        
        # Izračunaj širine kolona
        col_count = len(headers)
        col_widths = [0] * col_count
        
        # Proveri sve redove da nađeš maksimalnu dužinu
        all_rows = [headers] + data
        if totals:
            all_rows.append(totals)
        
        for row in all_rows:
            for i in range(col_count):
                if i < len(row):
                    # Ukloni boje za tačan izračun dužine
                    clean_cell = PerfectTable.strip_colors(str(row[i]))
                    col_widths[i] = max(col_widths[i], len(clean_cell))
        
        # Dodaj padding
        col_widths = [w + 2 for w in col_widths]
        
        # Ograniči širinu kolone fajlova (obično kolona 1)
        if len(col_widths) > 1:
            col_widths[1] = min(col_widths[1], max_file_width)
        
        # Funkcije za okvire
        def top_border():
            return "┌" + "┬".join("─" * w for w in col_widths) + "┐"
        
        def header_separator():
            return "├" + "┼".join("─" * w for w in col_widths) + "┤"
        
        def middle_separator():
            return "├" + "┼".join("─" * w for w in col_widths) + "┤"
        
        def bottom_border():
            return "└" + "┴".join("─" * w for w in col_widths) + "┘"
        
        def format_cell(cell, width, align="left", is_header=False, is_total=False):
            """Formatiraj ćeliju sa tačnim poravnanjem"""
            clean_cell = PerfectTable.strip_colors(str(cell))
            cell_len = len(clean_cell)
            
            if is_header:
                # Centrirano za zaglavlje
                padding = width - cell_len - 2  # -2 za razmake
                left_pad = padding // 2
                right_pad = padding - left_pad
                return f"{' ' * left_pad} {cell} {' ' * right_pad}"
            elif align == "right":
                # Desno poravnanje za brojeve
                padding = width - cell_len - 2
                return f"{' ' * padding} {cell} "
            else:
                # Levo poravnanje za tekst
                padding = width - cell_len - 2
                return f" {cell}{' ' * padding} "
        
        def format_row(cells, is_header=False, is_total=False):
            """Formatiraj ceo red"""
            row = "│"
            for i, cell in enumerate(cells):
                if i >= len(col_widths):
                    continue
                
                width = col_widths[i]
                
                # Odredi poravnanje
                if i == 0:  # Redni broj - centrirano
                    align = "center"
                elif i == len(cells) - 1 and len(cells) > 1:  # Poslednja kolona (brojevi) - desno
                    align = "right"
                else:  # Ostalo - levo
                    align = "left"
                
                formatted_cell = format_cell(
                    cell, width, align, 
                    is_header=is_header, 
                    is_total=is_total
                )
                row += formatted_cell + "│"
            return row
        
        # Kreiraj tabelu
        lines = []
        
        # Naslov
        if title:
            total_width = sum(col_widths) + len(col_widths) - 1
            title_line = "╔" + "═" * (total_width - 2) + "╗"
            title_text = f"║{Color.BOLD}{Color.CYAN}{title.center(total_width - 2)}{Color.RESET}║"
            lines.extend([title_line, title_text, "╠" + "═" * (total_width - 2) + "╣"])
        
        # Gornji okvir
        lines.append(top_border())
        
        # Zaglavlje
        lines.append(format_row(headers, is_header=True))
        lines.append(header_separator())
        
        # Podaci
        for i, row in enumerate(data):
            # Dodaj naizmenične boje za redove
            if i % 2 == 0:
                colored_row = []
                for j, cell in enumerate(row):
                    if j == 0:  # Redni broj
                        colored_row.append(f"{Color.GRAY}{cell}{Color.RESET}")
                    elif j == len(row) - 1:  # Broj linija
                        lines_num = PerfectTable.strip_colors(str(cell))
                        try:
                            num = int(lines_num)
                            if num > 500:
                                colored_row.append(f"{Color.RED}{num}{Color.RESET}")
                            elif num > 200:
                                colored_row.append(f"{Color.YELLOW}{num}{Color.RESET}")
                            elif num > 50:
                                colored_row.append(f"{Color.GREEN}{num}{Color.RESET}")
                            else:
                                colored_row.append(f"{Color.GRAY}{num}{Color.RESET}")
                        except:
                            colored_row.append(cell)
                    else:  # Naziv fajla
                        colored_row.append(f"{Color.WHITE}{cell}{Color.RESET}")
                lines.append(format_row(colored_row))
            else:
                lines.append(format_row(row))
        
        # Ukupno (ako postoji)
        if totals:
            lines.append(middle_separator())
            colored_totals = []
            for j, cell in enumerate(totals):
                if j == 0:
                    colored_totals.append(f"{Color.BOLD}{cell}{Color.RESET}")
                elif j == len(totals) - 1:
                    colored_totals.append(f"{Color.BOLD}{Color.GREEN}{cell}{Color.RESET}")
                else:
                    colored_totals.append(f"{Color.BOLD}{cell}{Color.RESET}")
            lines.append(format_row(colored_totals, is_total=True))
        
        # Donji okvir
        lines.append(bottom_border())
        
        return "\n".join(lines)
    
    @staticmethod
    def strip_colors(text):
        """Ukloni ANSI kodove iz teksta"""
        import re
        return re.sub(r'\033\[[0-9;]*m', '', text)
    
    @staticmethod
    def create_simple_table(files_data, directory_name=""):
        """Kreira jednostavnu tabelu za prikaz fajlova"""
        if not files_data:
            return ""
        
        # Pripremi podatke
        table_data = []
        for i, file_info in enumerate(files_data, 1):
            rel_path = file_info['rel_path']
            if len(rel_path) > 45:
                rel_path = "..." + rel_path[-42:]
            
            lines = file_info['lines']
            # Broj linija će biti formatiran kasnije
            table_data.append([rel_path, str(lines)])
        
        # Ukupno
        total_files = len(files_data)
        total_lines = sum(f['lines'] for f in files_data)
        totals = [f"{total_files} fajlova", str(total_lines)]
        
        # Naslov
        title = f"📁 PYTHON FAJLOVI - {directory_name}" if directory_name else "📁 PYTHON FAJLOVI"
        
        # Kreiraj tabelu
        return PerfectTable.create_table(
            headers=["FAJL", "LINIJA"],
            data=table_data,
            totals=totals,
            title=title,
            max_file_width=55
        )

class LineCounter:
    def __init__(self, directory="."):
        self.directory = Path(directory).resolve()
        self.files = []
        self.total_lines = 0
        
    def scan(self):
        """Skenira sve Python fajlove"""
        print(f"\n{Color.BOLD}{Color.CYAN}🔍 SKENIRANJE PYTHON FAJLOVA{Color.RESET}")
        print(f"{Color.GRAY}Direktorijum: {self.directory}{Color.RESET}")
        print(f"{Color.GRAY}Vreme: {datetime.now().strftime('%H:%M:%S')}{Color.RESET}")
        
        ignore_patterns = ['venv', '.venv', 'env', '.git', '__pycache__', '.idea', 'node_modules']
        
        file_count = 0
        for root, dirs, files in os.walk(self.directory):
            # Preskoči ignorisane direktorijume
            dirs[:] = [d for d in dirs if d not in ignore_patterns]
            
            for file in files:
                if file.endswith('.py'):
                    file_path = Path(root) / file
                    try:
                        # Broj linija
                        with open(file_path, 'r', encoding='utf-8') as f:
                            lines = len(f.readlines())
                        
                        # Relativna putanja
                        rel_path = file_path.relative_to(self.directory)
                        
                        self.files.append({
                            'path': file_path,
                            'rel_path': str(rel_path),
                            'name': file,
                            'lines': lines
                        })
                        
                        self.total_lines += lines
                        file_count += 1
                        
                        # Progress
                        sys.stdout.write(f"\r{Color.GREEN}✓{Color.RESET} Pročitano fajlova: {file_count}")
                        sys.stdout.flush()
                        
                    except Exception as e:
                        print(f"\n{Color.RED}✗ Greška: {file_path}{Color.RESET}")
        
        print(f"\n{Color.GREEN}✅ Skeniranje završeno!{Color.RESET}")
        return len(self.files)
    
    def display_results(self):
        """Prikazuje glavne rezultate"""
        if not self.files:
            print(f"\n{Color.RED}❌ Nema Python fajlova!{Color.RESET}")
            return
        
        # Sortiraj fajlove po putanji
        self.files.sort(key=lambda x: x['rel_path'].lower())
        
        # Prikaži tabelu
        table = PerfectTable.create_simple_table(
            self.files, 
            self.directory.name
        )
        print(f"\n{table}")
        
        # Prikaži statistiku
        self.display_statistics()
    
    def display_statistics(self):
        """Prikazuje detaljnu statistiku"""
        if not self.files:
            return
        
        total_files = len(self.files)
        avg_lines = self.total_lines / total_files if total_files > 0 else 0
        
        # Pronađi najveći i najmanji fajl
        largest = max(self.files, key=lambda x: x['lines'])
        smallest = min(self.files, key=lambda x: x['lines'])
        
        print(f"\n{Color.BOLD}{Color.CYAN}📊 STATISTIKA{Color.RESET}")
        print("┌─────────────────────────────────────────────┐")
        
        # Formatiramo sve brojeve da budu poravnati
        stats = [
            ("Ukupno fajlova:", f"{Color.YELLOW}{total_files:>6}{Color.RESET}"),
            ("Ukupno linija:", f"{Color.YELLOW}{self.total_lines:>8}{Color.RESET}"),
            ("Prosečno linija:", f"{Color.YELLOW}{avg_lines:>8.1f}{Color.RESET}"),
            ("Najveći fajl:", f"{Color.YELLOW}{largest['name']:>15}{Color.RESET} ({largest['lines']} linija)"),
            ("Najmanji fajl:", f"{Color.YELLOW}{smallest['name']:>15}{Color.RESET} ({smallest['lines']} linija)")
        ]
        
        for label, value in stats:
            print(f"│ {Color.BOLD}{label:<18}{Color.RESET} {value}")
        
        print("└─────────────────────────────────────────────┘")
    
    def display_directory_summary(self):
        """Prikazuje rezime po direktorijumima"""
        if not self.files:
            return
        
        # Grupiši po direktorijumu
        dir_stats = {}
        for file_info in self.files:
            dir_path = str(Path(file_info['rel_path']).parent)
            if dir_path == ".":
                dir_path = "<root>"
            
            if dir_path not in dir_stats:
                dir_stats[dir_path] = {'files': 0, 'lines': 0}
            
            dir_stats[dir_path]['files'] += 1
            dir_stats[dir_path]['lines'] += file_info['lines']
        
        # Sortiraj po broju linija (opadajuće)
        sorted_dirs = sorted(
            dir_stats.items(), 
            key=lambda x: x[1]['lines'], 
            reverse=True
        )
        
        # Pripremi podatke za tabelu
        table_data = []
        for dir_path, stats in sorted_dirs:
            # Formatiraj brojeve da budu desno poravnati
            files_str = f"{stats['files']:>4}"
            lines_str = f"{stats['lines']:>6}"
            table_data.append([dir_path, files_str, lines_str])
        
        # Ukupno
        total_files = len(self.files)
        totals = [
            "UKUPNO", 
            f"{Color.BOLD}{total_files:>4}{Color.RESET}", 
            f"{Color.BOLD}{self.total_lines:>6}{Color.RESET}"
        ]
        
        # Kreiraj tabelu
        title = f"{Color.CYAN}📂 DISTRIBUCIJA PO DIREKTORIJUMIMA{Color.RESET}"
        table = PerfectTable.create_table(
            headers=["DIREKTORIJUM", "FAJLOVI", "LINIJA"],
            data=table_data,
            totals=totals,
            title=title,
            max_file_width=40
        )
        
        print(f"\n{table}")

def main():
    """Glavna funkcija"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description=f'{Color.BOLD}Python Line Counter - Savršeno poravnate tabele{Color.RESET}',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f'''
{Color.GREEN}Primeri:{Color.RESET}
  {Color.CYAN}python counter.py{Color.RESET}                # Osnovni prikaz
  {Color.CYAN}python counter.py -d{Color.RESET}             # Sa direktorijumima
  {Color.CYAN}python counter.py C:\\projekat{Color.RESET}   # Drugi direktorijum
  {Color.CYAN}python counter.py --all{Color.RESET}          # Sve opcije
        '''
    )
    
    parser.add_argument('directory', nargs='?', default='.', 
                       help='Direktorijum za analizu')
    parser.add_argument('-d', '--dirs', action='store_true',
                       help='Prikaži grupisanje po direktorijumima')
    parser.add_argument('-a', '--all', action='store_true',
                       help='Prikaži sve informacije')
    
    args = parser.parse_args()
    
    # Proveri direktorijum
    if not os.path.isdir(args.directory):
        print(f"{Color.RED}❌ Direktorijum '{args.directory}' ne postoji!{Color.RESET}")
        return
    
    # Kreiraj counter
    counter = LineCounter(args.directory)
    
    try:
        # Skeniraj fajlove
        file_count = counter.scan()
        
        if file_count == 0:
            print(f"\n{Color.YELLOW}ℹ️  Nema Python fajlova za prikaz.{Color.RESET}")
            return
        
        # Prikaži rezultate
        print(f"\n{Color.GREEN}{'='*60}{Color.RESET}")
        counter.display_results()
        
        # Dodatne opcije
        if args.dirs or args.all:
            counter.display_directory_summary()
        
        print(f"\n{Color.BOLD}{Color.GREEN}✅ ANALIZA ZAVRŠENA{Color.RESET}")
        print(f"{Color.GRAY}Direktorijum: {counter.directory}{Color.RESET}")
        
    except KeyboardInterrupt:
        print(f"\n\n{Color.YELLOW}⏹️  Prekinuto{Color.RESET}")
    except Exception as e:
        print(f"\n{Color.RED}❌ Greška: {e}{Color.RESET}")

if __name__ == "__main__":
    # Proveri da li terminal podržava boje
    if sys.platform == "win32":
        os.system("color")  # Omogući boje u Windows CMD
        
    main()