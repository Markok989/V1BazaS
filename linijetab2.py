"""
Najjednostavnija verzija - samo tabela fajlova i ukupno
"""

import os

def main():
    # Proveri da li je dat direktorijum
    import sys
    dir_path = sys.argv[1] if len(sys.argv) > 1 else "."
    
    if not os.path.exists(dir_path):
        print(f"Direktorijum '{dir_path}' ne postoji!")
        return
    
    # Sakupi sve .py fajlove
    fajlovi = []
    for root, dirs, files in os.walk(dir_path):
        for file in files:
            if file.endswith('.py'):
                full_path = os.path.join(root, file)
                try:
                    with open(full_path, 'r', encoding='utf-8') as f:
                        line_count = len(f.readlines())
                    
                    # Relativna putanja
                    rel_path = os.path.relpath(full_path, dir_path)
                    fajlovi.append((rel_path, line_count))
                    
                except:
                    continue
    
    if not fajlovi:
        print("Nema Python fajlova!")
        return
    
    # Pronađi najdužu putanju za formatiranje
    max_len = max(len(path) for path, _ in fajlovi)
    max_len = min(max_len, 60)  # Ograniči
    
    # Ispiši tabelu
    print("\n" + "=" * (max_len + 12))
    print(f"{'FAJL':<{max_len}} {'LINIJA':>10}")
    print("=" * (max_len + 12))
    
    ukupno = 0
    for path, lines in sorted(fajlovi):
        # Skrati dug putanju
        if len(path) > max_len:
            path = "..." + path[-(max_len-3):]
        
        print(f"{path:<{max_len}} {lines:>10}")
        ukupno += lines
    
    print("-" * (max_len + 12))
    print(f"{'UKUPNO:':<{max_len}} {ukupno:>10}")
    print("=" * (max_len + 12))
    print(f"\nUkupno fajlova: {len(fajlovi)}")

if __name__ == "__main__":
    main()