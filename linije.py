"""
Skripta za brojanje linija koda u Python fajlovima (.py)
"""

import os

def broj_linija_pajton_koda(direktorijum=".", detaljno=False):
    """
    Broji linije koda u .py fajlovima.
    
    Args:
        direktorijum: Početni direktorijum (podrazumevano trenutni)
        detaljno: Da li da prikaže detaljne statistike
    
    Returns:
        Rezultati brojanja
    """
    ukupno_linija = 0
    broj_fajlova = 0
    linije_koda = 0
    prazne_linije = 0
    linije_komentara = 0
    
    print(f"Pretraga direktorijuma: {os.path.abspath(direktorijum)}\n")
    
    for koren, dirs, fajlovi in os.walk(direktorijum):
        for fajl in fajlovi:
            if fajl.endswith('.py'):
                putanja = os.path.join(koren, fajl)
                
                try:
                    with open(putanja, 'r', encoding='utf-8') as f:
                        linije = f.readlines()
                    
                    br_linija = len(linije)
                    ukupno_linija += br_linija
                    broj_fajlova += 1
                    
                    if detaljno:
                        kod = 0
                        prazne = 0
                        komentari = 0
                        
                        for linija in linije:
                            linija_stripped = linija.strip()
                            if not linija_stripped:
                                prazne += 1
                            elif linija_stripped.startswith('#'):
                                komentari += 1
                            else:
                                kod += 1
                        
                        linije_koda += kod
                        prazne_linije += prazne
                        linije_komentara += komentari
                        
                        print(f"{putanja}: {br_linija} linija (kod: {kod}, prazne: {prazne}, komentari: {komentari})")
                    else:
                        print(f"{putanja}: {br_linija} linija")
                        
                except Exception as e:
                    print(f"❌ Greška pri čitanju {putanja}: {e}")
    
    # Prikaz rezultata
    print(f"\n{'='*60}")
    print("REZULTATI BROJANJA:")
    print(f"{'='*60}")
    print(f"📁 Broj Python fajlova: {broj_fajlova}")
    print(f"📊 Ukupan broj linija:  {ukupno_linija}")
    
    if detaljno:
        print(f"\n📈 Detaljna statistika:")
        print(f"   • Linije koda:     {linije_koda} ({linije_koda/ukupno_linija*100 if ukupno_linija else 0:.1f}%)")
        print(f"   • Prazne linije:   {prazne_linije} ({prazne_linije/ukupno_linija*100 if ukupno_linija else 0:.1f}%)")
        print(f"   • Linije komentara: {linije_komentara} ({linije_komentara/ukupno_linija*100 if ukupno_linija else 0:.1f}%)")
    
    print(f"\n📍 Direktorijum: {os.path.abspath(direktorijum)}")
    print(f"{'='*60}")
    
    return {
        'fajlovi': broj_fajlova,
        'ukupno_linija': ukupno_linija,
        'linije_koda': linije_koda if detaljno else None,
        'prazne_linije': prazne_linije if detaljno else None,
        'linije_komentara': linije_komentara if detaljno else None
    }

if __name__ == "__main__":
    import sys
    
    # Provera argumenata
    direktorijum = "."
    detaljno = False
    
    if len(sys.argv) > 1:
        for arg in sys.argv[1:]:
            if arg in ["-d", "--detaljno"]:
                detaljno = True
            elif os.path.isdir(arg):
                direktorijum = arg
            elif arg in ["-h", "--help"]:
                print("\n📝 UPUTSTVO ZA KORIŠĆENJE:")
                print("python count_lines.py [direktorijum] [opcije]")
                print("\nOpcije:")
                print("  -d, --detaljno  Prikaži detaljne statistike (kod/prazne/komentari)")
                print("  -h, --help      Prikaži ovu pomoć")
                print("\nPrimeri:")
                print("  python count_lines.py                # Broji u trenutnom direktorijumu")
                print("  python count_lines.py -d             # Detaljno u trenutnom direktorijumu")
                print("  python count_lines.py ../moj_projekat # Broji u drugom direktorijumu")
                print("  python count_lines.py ../projekat -d # Detaljno u drugom direktorijumu")
                sys.exit(0)
    
    # Pokretanje brojanja
    print(f"\n🔍 Počinjem brojanje Python fajlova...")
    rezultati = broj_linija_pajton_koda(direktorijum, detaljno)