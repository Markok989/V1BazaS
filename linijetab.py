"""
Skripta za brojanje linija koda u Python fajlovima (.py) sa tabelarnim prikazom
"""

import os
from datetime import datetime

class PythonLineCounter:
    def __init__(self, directory=".", detailed=False, ignore_dirs=None):
        self.directory = directory
        self.detailed = detailed
        self.ignore_dirs = ignore_dirs or ['venv', '.venv', 'env', '.git', '__pycache__', '.idea', 'node_modules']
        
        # Rezultati
        self.total_files = 0
        self.total_lines = 0
        self.code_lines = 0
        self.empty_lines = 0
        self.comment_lines = 0
        self.file_stats = []
    
    def count_lines_in_file(self, filepath):
        """Broji linije u jednom fajlu."""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            line_count = len(lines)
            stats = {'file': filepath, 'lines': line_count}
            
            if self.detailed:
                code = empty = comments = 0
                for line in lines:
                    stripped = line.strip()
                    if not stripped:
                        empty += 1
                    elif stripped.startswith('#'):
                        comments += 1
                    else:
                        code += 1
                
                stats.update({
                    'code': code,
                    'empty': empty,
                    'comments': comments
                })
            
            return stats
            
        except Exception as e:
            return {'file': filepath, 'error': str(e)}
    
    def scan_directory(self):
        """Skenira direktorijum i broji linije."""
        print(f"\n🔍 Skeniranje: {os.path.abspath(self.directory)}")
        
        for root, dirs, files in os.walk(self.directory):
            # Ignoriši nepotrebne direktorijume
            dirs[:] = [d for d in dirs if d not in self.ignore_dirs]
            
            for file in files:
                if file.endswith('.py'):
                    filepath = os.path.join(root, file)
                    stats = self.count_lines_in_file(filepath)
                    
                    if 'error' not in stats:
                        self.file_stats.append(stats)
                        self.total_files += 1
                        self.total_lines += stats['lines']
                        
                        if self.detailed:
                            self.code_lines += stats.get('code', 0)
                            self.empty_lines += stats.get('empty', 0)
                            self.comment_lines += stats.get('comments', 0)
    
    def print_results_table(self):
        """Štampa rezultate u tabelarnom formatu."""
        print("\n" + "="*80)
        print("📊 REZULTATI BROJANJA PYTHON KODA")
        print("="*80)
        
        # Osnovni pregled
        print("\n📁 OSNOVNE INFORMACIJE:")
        print("-"*40)
        print(f"Direktorijum:     {os.path.abspath(self.directory)}")
        print(f"Datum skeniranja: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Tabela sa statistikama fajlova (ako nema previše fajlova)
        if self.total_files <= 20:
            print("\n📄 FAJLOVI:")
            print("-"*80)
            if self.detailed:
                print(f"{'FAJL':<50} {'UKUPNO':<8} {'KOD':<8} {'PRAZNE':<8} {'KOMENTARI':<8}")
                print("-"*80)
                for stats in self.file_stats:
                    rel_path = os.path.relpath(stats['file'], self.directory)
                    if len(rel_path) > 47:
                        rel_path = "..." + rel_path[-44:]
                    print(f"{rel_path:<50} {stats['lines']:<8} {stats.get('code', 'N/A'):<8} "
                          f"{stats.get('empty', 'N/A'):<8} {stats.get('comments', 'N/A'):<8}")
            else:
                print(f"{'FAJL':<60} {'LINIJA':<10}")
                print("-"*80)
                for stats in self.file_stats:
                    rel_path = os.path.relpath(stats['file'], self.directory)
                    if len(rel_path) > 58:
                        rel_path = "..." + rel_path[-55:]
                    print(f"{rel_path:<60} {stats['lines']:<10}")
        
        # Ukupna statistika
        print("\n📈 UKUPNA STATISTIKA:")
        print("-"*40)
        print(f"Broj Python fajlova: {self.total_files}")
        
        if self.detailed:
            print(f"\n{'STATISTIKA':<20} {'BROJ':<10} {'%':<10}")
            print("-"*40)
            
            stats_data = [
                ("Ukupno linija", self.total_lines, 100),
                ("Linije koda", self.code_lines, 
                 (self.code_lines/self.total_lines*100) if self.total_lines else 0),
                ("Prazne linije", self.empty_lines, 
                 (self.empty_lines/self.total_lines*100) if self.total_lines else 0),
                ("Linije komentara", self.comment_lines, 
                 (self.comment_lines/self.total_lines*100) if self.total_lines else 0)
            ]
            
            for name, count, percent in stats_data:
                print(f"{name:<20} {count:<10} {percent:.1f}%")
            
            # Progress bar vizuelizacija
            print(f"\n📊 PROPORCIJA:")
            if self.total_lines > 0:
                total_width = 40
                code_width = int((self.code_lines / self.total_lines) * total_width)
                empty_width = int((self.empty_lines / self.total_lines) * total_width)
                comment_width = total_width - code_width - empty_width
                
                print("[" + "█"*code_width + "░"*empty_width + "▓"*comment_width + "]")
                print(f"█ Kod ({self.code_lines/self.total_lines*100:.1f}%) | "
                      f"░ Prazne ({self.empty_lines/self.total_lines*100:.1f}%) | "
                      f"▓ Komentari ({self.comment_lines/self.total_lines*100:.1f}%)")
        else:
            print(f"Ukupno linija koda: {self.total_lines}")
        
        # Dodatne informacije
        print("\n📋 DODATNE INFORMACIJE:")
        print("-"*40)
        if self.total_files > 0:
            avg_lines = self.total_lines / self.total_files
            print(f"Prosečno linija po fajlu: {avg_lines:.1f}")
            
            # Pronađi najveći i najmanji fajl
            if self.file_stats:
                largest = max(self.file_stats, key=lambda x: x['lines'])
                smallest = min(self.file_stats, key=lambda x: x['lines'])
                print(f"Najveći fajl: {os.path.basename(largest['file'])} ({largest['lines']} linija)")
                print(f"Najmanji fajl: {os.path.basename(smallest['file'])} ({smallest['lines']} linija)")
        
        print("\n" + "="*80)
        print("✅ BROJANJE ZAVRŠENO")
        print("="*80)

def main():
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Broji linije Python koda sa tabelarnim prikazom',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Primeri korišćenja:
  python linecounter.py                    # Osnovno brojanje
  python linecounter.py -d                 # Detaljno sa statistikama
  python linecounter.py ../projekat        # Brojanje u drugom direktorijumu
  python linecounter.py -d --no-table      # Detaljno bez tabele fajlova
  python linecounter.py --ignore venv,node_modules  # Ignoriši određene direktorijume
        '''
    )
    
    parser.add_argument('directory', nargs='?', default='.', 
                       help='Direktorijum za skeniranje (podrazumevano: trenutni)')
    parser.add_argument('-d', '--detailed', action='store_true',
                       help='Prikaži detaljne statistike (kod/prazne/komentari)')
    parser.add_argument('-i', '--ignore', default='venv,.venv,env,.git,__pycache__,.idea,node_modules',
                       help='Direktorijumi za ignorisanje (odvojeni zarezom)')
    parser.add_argument('--no-table', action='store_true',
                       help='Ne prikazuj tabelu sa fajlovima')
    
    args = parser.parse_args()
    
    # Kreiraj counter
    counter = PythonLineCounter(
        directory=args.directory,
        detailed=args.detailed,
        ignore_dirs=args.ignore.split(',')
    )
    
    # Pokreni skeniranje
    counter.scan_directory()
    
    # Prikaži rezultate
    counter.print_results_table()
    
    # Export opcija (dodatno)
    export = input("\n💾 Da li želite da sačuvate rezultate u fajl? (d/n): ")
    if export.lower() in ['d', 'da', 'y', 'yes']:
        filename = f"python_stats_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, 'w', encoding='utf-8') as f:
            import io
            import sys
            
            # Preusmeri stdout u string
            old_stdout = sys.stdout
            sys.stdout = io.StringIO()
            
            # Ponovo ispiši rezultate
            counter.print_results_table()
            
            # Vrati stdout
            result = sys.stdout.getvalue()
            sys.stdout = old_stdout
            
            # Zapiši u fajl
            f.write(result)
            print(f"✅ Rezultati sačuvani u: {filename}")

if __name__ == "__main__":
    main()