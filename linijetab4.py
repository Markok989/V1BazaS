"""
Modern Python Line Counter sa poboljšanim tabelarnim prikazom za PowerShell
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
    BG_BLUE = "\033[44m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"

class EnhancedTable:
    """Klasa za kreiranje poboljšanih tabela"""
    
    @staticmethod
    def create_boxed_table(headers, data, totals=None, title=None, max_width=80):
        """
        Kreira tabelu sa okvirom i bojama
        """
        # Dodaj redne brojeve
        headers_with_num = ["#"] + list(headers)
        data_with_num = [[str(i+1)] + list(row) for i, row in enumerate(data)]
        
        if totals:
            totals_with_num = [""] + list(totals)
        
        # Izračunaj širine kolona
        col_widths = []
        all_rows = [headers_with_num] + data_with_num
        if totals:
            all_rows.append(totals_with_num)
        
        for col_idx in range(len(headers_with_num)):
            max_len = 0
            for row in all_rows:
                if col_idx < len(row):
                    cell = str(row[col_idx])
                    # Ukloni ANSI kodove za izračunavanje dužine
                    clean_cell = EnhancedTable._remove_ansi(cell)
                    max_len = max(max_len, len(clean_cell))
            col_widths.append(max_len + 2)  # Dodaj padding
        
        # Ograniči ukupnu širinu
        total_width = sum(col_widths) + len(col_widths) + 1
        if total_width > max_width:
            # Skrati prvu kolonu (putanju)
            excess = total_width - max_width
            col_widths[1] = max(20, col_widths[1] - excess)
        
        # Funkcije za okvire
        def top_border():
            return "╔" + "╦".join("═" * w for w in col_widths) + "╗"
        
        def header_separator():
            return "╠" + "╬".join("═" * w for w in col_widths) + "╣"
        
        def row_separator():
            return "╟" + "╫".join("─" * w for w in col_widths) + "╢"
        
        def total_separator():
            return "╠" + "╬".join("═" * w for w in col_widths) + "╣"
        
        def bottom_border():
            return "╚" + "╩".join("═" * w for w in col_widths) + "╝"
        
        def format_row(cells, is_header=False, is_total=False):
            row = "║"
            for i, cell in enumerate(cells):
                if i >= len(col_widths):
                    continue
                    
                clean_cell = EnhancedTable._remove_ansi(str(cell))
                padding = col_widths[i] - len(clean_cell) - 1
                
                if is_header:
                    # Centrirano za zaglavlje
                    formatted = f" {Color.BOLD}{Color.CYAN}{cell}{Color.RESET} "
                    left_pad = padding // 2
                    right_pad = padding - left_pad
                    row += f"{' ' * left_pad}{formatted}{' ' * right_pad}║"
                elif is_total:
                    # Bold za ukupno
                    formatted = f" {Color.BOLD}{Color.GREEN}{cell}{Color.RESET} "
                    row += formatted.ljust(col_widths[i] - 1) + "║"
                else:
                    # Levo poravnanje za podatke
                    formatted = f" {cell}{Color.RESET} "
                    row += formatted.ljust(col_widths[i] - 1) + "║"
            return row
        
        # Kreiraj tabelu
        lines = []
        
        # Naslov (ako postoji)
        if title:
            title_width = sum(col_widths) + len(col_widths) - 1
            title_line = f"╔{'═' * (title_width - 2)}╗"
            title_text = f"║{Color.BOLD}{Color.BG_BLUE}{title.center(title_width - 2)}{Color.RESET}║"
            lines.extend([title_line, title_text, header_separator()])
        else:
            lines.append(top_border())
        
        # Zaglavlje
        lines.append(format_row(headers_with_num, is_header=True))
        lines.append(header_separator())
        
        # Podaci
        for i, row in enumerate(data_with_num):
            # Dodaj boju naizmenično
            if i % 2 == 0:
                row = [f"{Color.GRAY}{cell}{Color.RESET}" if j == 1 else cell 
                      for j, cell in enumerate(row)]
            lines.append(format_row(row))
            if i < len(data_with_num) - 1:
                lines.append(row_separator())
        
        # Ukupno (ako postoji)
        if totals:
            lines.append(total_separator())
            lines.append(format_row(totals_with_num, is_total=True))
        
        # Donji okvir
        lines.append(bottom_border())
        
        return "\n".join(lines)
    
    @staticmethod
    def _remove_ansi(text):
        """Ukloni ANSI kodove iz teksta"""
        import re
        return re.sub(r'\033\[[0-9;]*m', '', text)

class PythonLineCounter:
    def __init__(self, directory="."):
        self.directory = Path(directory).resolve()
        self.files = []
        self.total_lines = 0
        
    def scan(self):
        """Skenira Python fajlove i broji linije"""
        print(f"\n{Color.BOLD}{Color.BLUE}🔍 SKENIRANJE PYTHON FAJLOVA{Color.RESET}")
        print(f"{Color.GRAY}Direktorijum: {self.directory}{Color.RESET}")
        print(f"{Color.GRAY}Vreme: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Color.RESET}")
        print()
        
        ignore_dirs = {'venv', '.venv', 'env', '.git', '__pycache__', '.idea', 'node_modules'}
        
        for py_file in self.directory.rglob("*.py"):
            # Preskoči ignorisane direktorijume
            if any(ignore in py_file.parts for ignore in ignore_dirs):
                continue
            
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                
                line_count = len(lines)
                rel_path = py_file.relative_to(self.directory)
                
                self.files.append({
                    'path': py_file,
                    'rel_path': str(rel_path),
                    'name': py_file.name,
                    'lines': line_count,
                    'dir': str(rel_path.parent) if rel_path.parent != Path('.') else "."
                })
                
                self.total_lines += line_count
                
                # Progress indicator
                sys.stdout.write(f"\r{Color.GREEN}✓{Color.RESET} Pronađeno: {len(self.files)} fajlova, {self.total_lines} linija")
                sys.stdout.flush()
                
            except Exception as e:
                print(f"\n{Color.RED}✗ Greška: {py_file} - {e}{Color.RESET}")
        
        print(f"\n\n{Color.GREEN}✅ Skeniranje završeno!{Color.RESET}")
    
    def display_summary(self):
        """Prikazuje kratak pregled"""
        if not self.files:
            print(f"\n{Color.RED}{Color.BOLD}❌ NEMA PYTHON FAJLOVA!{Color.RESET}")
            return
        
        avg_lines = self.total_lines / len(self.files)
        largest = max(self.files, key=lambda x: x['lines'])
        smallest = min(self.files, key=lambda x: x['lines'])
        
        print(f"\n{Color.BOLD}{Color.CYAN}📊 REZIME:{Color.RESET}")
        print(f"{'─' * 50}")
        print(f"{Color.BOLD}• Ukupno fajlova:{Color.RESET}  {Color.YELLOW}{len(self.files):>4}{Color.RESET}")
        print(f"{Color.BOLD}• Ukupno linija:{Color.RESET}   {Color.YELLOW}{self.total_lines:>4}{Color.RESET}")
        print(f"{Color.BOLD}• Prosečno:{Color.RESET}        {Color.YELLOW}{avg_lines:>7.1f}{Color.RESET} linija/fajl")
        print(f"{Color.BOLD}• Najveći:{Color.RESET}        {Color.YELLOW}{largest['name']:>15}{Color.RESET} ({largest['lines']} linija)")
        print(f"{Color.BOLD}• Najmanji:{Color.RESET}       {Color.YELLOW}{smallest['name']:>15}{Color.RESET} ({smallest['lines']} linija)")
        print(f"{'─' * 50}")
    
    def display_detailed_table(self, max_files=50):
        """Prikazuje detaljnu tabelu sa fajlovima"""
        if not self.files:
            return
        
        # Sortiraj fajlove
        sorted_files = sorted(self.files, key=lambda x: x['rel_path'].lower())
        
        # Ograniči prikaz ako ima previše fajlova
        display_files = sorted_files
        if len(sorted_files) > max_files:
            print(f"\n{Color.YELLOW}⚠️  Pronađeno {len(sorted_files)} fajlova. Prikazujem prvih {max_files}.{Color.RESET}")
            display_files = sorted_files[:max_files]
        
        # Pripremi podatke za tabelu
        table_data = []
        for file_info in display_files:
            rel_path = file_info['rel_path']
            if len(rel_path) > 40:
                rel_path = "..." + rel_path[-37:]
            
            # Dodaj boju za fajlove prema veličini
            lines = file_info['lines']
            if lines > 500:
                lines_str = f"{Color.RED}{lines}{Color.RESET}"
            elif lines > 200:
                lines_str = f"{Color.YELLOW}{lines}{Color.RESET}"
            elif lines > 50:
                lines_str = f"{Color.GREEN}{lines}{Color.RESET}"
            else:
                lines_str = f"{Color.GRAY}{lines}{Color.RESET}"
            
            table_data.append([rel_path, lines_str])
        
        # Ukupni red
        totals = [
            f"{Color.BOLD}{len(self.files)} fajlova{Color.RESET}",
            f"{Color.BOLD}{self.total_lines}{Color.RESET}"
        ]
        
        # Naslov tabele
        title = f"{Color.BOLD}📁 PYTHON FAJLOVI - {self.directory.name}{Color.RESET}"
        
        # Kreiraj i prikaži tabelu
        table = EnhancedTable.create_boxed_table(
            headers=["FAJL", "LINIJA"],
            data=table_data,
            totals=totals,
            title=title,
            max_width=100
        )
        
        print(f"\n{table}")
        
        # Ako nisu prikazani svi fajlovi
        if len(sorted_files) > max_files:
            remaining = len(sorted_files) - max_files
            print(f"\n{Color.GRAY}... i još {remaining} fajlova nije prikazano.{Color.RESET}")
    
    def display_by_directory(self):
        """Grupisanje po direktorijumima"""
        if not self.files:
            return
        
        # Grupiši po direktorijumu
        dir_stats = {}
        for file_info in self.files:
            dir_path = file_info['dir']
            if dir_path not in dir_stats:
                dir_stats[dir_path] = {'files': 0, 'lines': 0}
            dir_stats[dir_path]['files'] += 1
            dir_stats[dir_path]['lines'] += file_info['lines']
        
        # Sortiraj po broju linija
        sorted_dirs = sorted(dir_stats.items(), key=lambda x: x[1]['lines'], reverse=True)
        
        # Pripremi podatke za tabelu
        table_data = []
        for dir_path, stats in sorted_dirs:
            if dir_path == ".":
                dir_display = f"{Color.BOLD}<root>{Color.RESET}"
            else:
                dir_display = dir_path
            
            # Boje za statistikue
            files_str = f"{Color.CYAN}{stats['files']}{Color.RESET}"
            lines_str = f"{Color.YELLOW}{stats['lines']}{Color.RESET}"
            
            table_data.append([dir_display, files_str, lines_str])
        
        # Ukupno
        total_files = len(self.files)
        totals = [
            f"{Color.BOLD}{total_files} fajlova{Color.RESET}",
            f"{Color.BOLD}{total_files}{Color.RESET}",
            f"{Color.BOLD}{self.total_lines}{Color.RESET}"
        ]
        
        # Tabela
        title = f"{Color.BOLD}📂 DISTRIBUCIJA PO DIREKTORIJUMIMA{Color.RESET}"
        table = EnhancedTable.create_boxed_table(
            headers=["DIREKTORIJUM", "FAJLOVI", "LINIJA"],
            data=table_data,
            totals=totals,
            title=title
        )
        
        print(f"\n{table}")
    
    def display_size_chart(self):
        """Prikazuje grafički prikaz veličina fajlova"""
        if not self.files:
            return
        
        # Kategorije po veličini
        categories = {
            "Vrlo mali (< 50)": 0,
            "Mali (50-200)": 0,
            "Srednji (200-500)": 0,
            "Veliki (500-1000)": 0,
            "Vrlo veliki (> 1000)": 0
        }
        
        for file_info in self.files:
            lines = file_info['lines']
            if lines < 50:
                categories["Vrlo mali (< 50)"] += 1
            elif lines < 200:
                categories["Mali (50-200)"] += 1
            elif lines < 500:
                categories["Srednji (200-500)"] += 1
            elif lines < 1000:
                categories["Veliki (500-1000)"] += 1
            else:
                categories["Vrlo veliki (> 1000)"] += 1
        
        # Pripremi podatke za tabelu
        table_data = []
        for category, count in categories.items():
            if count > 0:
                percentage = (count / len(self.files)) * 100
                bar = "█" * int(percentage / 5)  # 5% po karakteru
                bar_display = f"{Color.GREEN}{bar}{Color.RESET}"
                
                table_data.append([
                    category,
                    f"{Color.CYAN}{count}{Color.RESET}",
                    f"{Color.YELLOW}{percentage:.1f}%{Color.RESET}",
                    bar_display
                ])
        
        if table_data:
            title = f"{Color.BOLD}📏 DISTRIBUCIJA PO VELIČINI{Color.RESET}"
            table = EnhancedTable.create_boxed_table(
                headers=["KATEGORIJA", "FAJLOVI", "PROCENAT", "GRAFIKON"],
                data=table_data,
                title=title
            )
            print(f"\n{table}")

def main():
    """Glavna funkcija"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description=f'{Color.BOLD}Modern Python Line Counter{Color.RESET}',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f'''
{Color.GREEN}Primeri:{Color.RESET}
  {Color.CYAN}python linecounter.py{Color.RESET}              # Osnovno
  {Color.CYAN}python linecounter.py -d{Color.RESET}           # Sa grupisanjem po direktorijumima
  {Color.CYAN}python linecounter.py -c{Color.RESET}           # Sa grafikonom
  {Color.CYAN}python linecounter.py ../projekat{Color.RESET}  # Drugi direktorijum
  {Color.CYAN}python linecounter.py --all{Color.RESET}        # Sve opcije
        '''
    )
    
    parser.add_argument('directory', nargs='?', default='.', 
                       help='Direktorijum za skeniranje')
    parser.add_argument('-d', '--dirs', action='store_true',
                       help='Prikaži grupisanje po direktorijumima')
    parser.add_argument('-c', '--chart', action='store_true',
                       help='Prikaži grafički prikaz veličina')
    parser.add_argument('--all', action='store_true',
                       help='Prikaži sve opcije')
    
    args = parser.parse_args()
    
    # Proveri direktorijum
    if not os.path.isdir(args.directory):
        print(f"{Color.RED}❌ Direktorijum '{args.directory}' ne postoji!{Color.RESET}")
        return
    
    # Kreiraj counter
    counter = PythonLineCounter(args.directory)
    
    # Skeniraj
    try:
        counter.scan()
        
        # Prikaži rezultate
        if not counter.files:
            return
        
        # Odredi šta da prikaže
        show_all = args.all or (not args.dirs and not args.chart)
        
        if show_all or True:  # Uvek prikaži osnovno
            counter.display_summary()
            counter.display_detailed_table()
        
        if args.dirs or args.all:
            counter.display_by_directory()
        
        if args.chart or args.all:
            counter.display_size_chart()
        
        print(f"\n{Color.BOLD}{Color.GREEN}🎉 ANALIZA ZAVRŠENA!{Color.RESET}")
        
    except KeyboardInterrupt:
        print(f"\n\n{Color.YELLOW}⏹️  Prekinuto od strane korisnika{Color.RESET}")
    except Exception as e:
        print(f"\n{Color.RED}❌ Greška: {e}{Color.RESET}")

if __name__ == "__main__":
    main()