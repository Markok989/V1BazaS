"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║   🐍 PYTHON LINE COUNTER PREMIUM 2.0 - SA VRHUNSKIM DIZAJNOM                 ║
║   Savršeno poravnate tabele | Analiza kompleksnosti | Live Preview          ║
║   Git integracija | Dupli fajlovi | Export | Vizuelizacija                  ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""

import os
import sys
import json
import time
import csv
import re
import hashlib
import subprocess
import argparse
import importlib.util
from datetime import datetime
from pathlib import Path
from collections import defaultdict, Counter

# ==============================================================================
# 🎨 KOLOR SHEMA - PREMIUM PALETA
# ==============================================================================

class Color:
    """Premium ANSI kodovi za savršene boje"""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"
    BLINK = "\033[5m"
    REVERSE = "\033[7m"
    
    # Premium paleta
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    GRAY = "\033[90m"
    
    # Bright varijante
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"
    
    # Pozadine
    BG_BLACK = "\033[40m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"
    BG_MAGENTA = "\033[45m"
    BG_CYAN = "\033[46m"
    BG_WHITE = "\033[47m"


# ==============================================================================
# ⚙️ NAPREDNA KONFIGURACIJA SA PAMĆENJEM
# ==============================================================================

class Config:
    """Premium konfiguracija sa automatskim čuvanjem"""
    
    DEFAULT = {
        # Prikaz
        'colors': True,
        'unicode_chars': True,
        'max_file_width': 45,
        'show_hidden': False,
        'show_progress': True,
        'show_sparklines': True,
        
        # Sortiranje
        'sort_by': 'path',  # path, lines, size, complexity
        'sort_reverse': False,
        
        # Ignorisanje
        'ignore_patterns': [
            'venv', '.venv', 'env', '.env', 
            '.git', '__pycache__', '.idea', '.vscode',
            'node_modules', 'dist', 'build', '*.pyc',
            '.pytest_cache', '.mypy_cache', '.coverage'
        ],
        
        # Keš
        'cache_timeout': 3600,  # 1 sat
        'use_cache': True,
        
        # Pragovi
        'large_file_threshold': 500,  # linija
        'complexity_thresholds': {
            'low': 20,
            'medium': 50,
            'high': 100
        },
        
        # Export
        'export_decimal_places': 2,
        'export_include_complexity': True,
        
        # Live preview
        'live_preview_debounce': 1.0,
        'live_preview_recursive': True,
    }
    
    def __init__(self, config_file=".pycounter_config.json"):
        self.config_file = config_file
        self.config = self._load()
    
    def _load(self):
        """Učitava konfiguraciju"""
        config = self.DEFAULT.copy()
        
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    user_config = json.load(f)
                    config.update(user_config)
                print(f"{Color.DIM}⚙️  Konfiguracija učitana iz {self.config_file}{Color.RESET}")
            except Exception as e:
                print(f"{Color.YELLOW}⚠️  Greška pri učitavanju konfiguracije: {e}{Color.RESET}")
        
        return config
    
    def save(self):
        """Čuva konfiguraciju"""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
            return True
        except Exception:
            return False
    
    def get(self, key, default=None):
        return self.config.get(key, default)
    
    def set(self, key, value):
        self.config[key] = value
        self.save()


# ==============================================================================
# 💾 PREMIUM CACHE SISTEM SA HASH INDEXIRANJEM
# ==============================================================================

class PremiumCache:
    """Napredni keš sistem sa MD5 hash indeksiranjem"""
    
    def __init__(self, cache_file=".pycounter_cache.json"):
        self.cache_file = cache_file
        self.cache = self._load()
    
    def _load(self):
        """Učitava keš"""
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r', encoding='utf-8') as f:
                    cache = json.load(f)
                
                # Proveri validnost
                cache_time = cache.get('timestamp', 0)
                if time.time() - cache_time < Config.DEFAULT['cache_timeout']:
                    return cache
                else:
                    print(f"{Color.DIM}ℹ️  Keš istekao, ponovno skeniranje...{Color.RESET}")
            except Exception:
                pass
        
        return {
            'version': '2.0',
            'timestamp': 0,
            'files': {},
            'hash_index': {},
            'stats': {}
        }
    
    def save(self, files_data, stats=None):
        """Čuva keš"""
        cache_entry = {
            'version': '2.0',
            'timestamp': time.time(),
            'files': {},
            'hash_index': {},
            'stats': stats or {}
        }
        
        for f in files_data:
            key = str(f['rel_path'])
            cache_entry['files'][key] = {
                'lines': f['lines'],
                'size': f['size'],
                'modified': f.get('modified', time.time()),
                'hash': f.get('hash', ''),
                'complexity': f.get('complexity_score', 0)
            }
            
            if 'hash' in f:
                cache_entry['hash_index'][f['hash']] = key
        
        try:
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(cache_entry, f, indent=2)
            print(f"{Color.DIM}💾 Keš sačuvan: {len(files_data)} fajlova{Color.RESET}")
        except Exception as e:
            print(f"{Color.YELLOW}⚠️  Greška pri čuvanju keša: {e}{Color.RESET}")
    
    def get(self, file_path, modified_time):
        """Dohvata keširani fajl"""
        key = str(file_path)
        cached = self.cache.get('files', {}).get(key)
        
        if cached and cached.get('modified', 0) == modified_time:
            return cached
        return None
    
    def invalidate(self):
        """Briše keš"""
        self.cache = {
            'version': '2.0',
            'timestamp': 0,
            'files': {},
            'hash_index': {},
            'stats': {}
        }
        self.save([], {})
        print(f"{Color.GREEN}✅ Keš memorija resetovana{Color.RESET}")
    
    def get_stats(self):
        """Vraća statistiku keša"""
        return {
            'files': len(self.cache.get('files', {})),
            'hashes': len(self.cache.get('hash_index', {})),
            'age': time.time() - self.cache.get('timestamp', 0),
            'version': self.cache.get('version', 'unknown')
        }


# ==============================================================================
# 🧠 NAPREDNA ANALIZA KOMPLEKSNOSTI KODA
# ==============================================================================

class CodeComplexityAnalyzer:
    """Sveobuhvatna analiza Python koda sa 10+ metrika"""
    
    # Regex obrasci za prepoznavanje
    PATTERNS = {
        'class': r'^\s*class\s+\w+',
        'function': r'^\s*def\s+\w+\s*\(',
        'async_function': r'^\s*async\s+def\s+\w+\s*\(',
        'decorator': r'^\s*@\w+',
        'import': r'^\s*(?:from\s+[\w.]+\s+)?import\s+',
        'if': r'^\s*if\s+',
        'elif': r'^\s*elif\s+',
        'else': r'^\s*else\s*:',
        'for': r'^\s*for\s+',
        'while': r'^\s*while\s+',
        'try': r'^\s*try\s*:',
        'except': r'^\s*except\s+',
        'finally': r'^\s*finally\s*:',
        'with': r'^\s*with\s+',
        'lambda': r'\blambda\b',
        'comprehension': r'\[.*for.*in.*\]|\{.*for.*in.*\}',
        'generator': r'\(.*for.*in.*\)',
        'assert': r'^\s*assert\s+',
        'return': r'^\s*return\s+',
        'yield': r'^\s*yield\s+',
        'global': r'^\s*global\s+',
        'nonlocal': r'^\s*nonlocal\s+',
    }
    
    @classmethod
    def analyze(cls, file_path):
        """Potpuna analiza Python fajla"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
            
            metrics = {
                'classes': 0,
                'functions': 0,
                'async_functions': 0,
                'decorators': 0,
                'imports': 0,
                'comments': 0,
                'docstrings': 0,
                'todo': 0,
                'fixme': 0,
                'xxx': 0,
                'empty_lines': 0,
                'control_structures': defaultdict(int),
                'complexity_score': 0,
                'cognitive_complexity': 0,
                'maintainability_index': 0,
                'lines_of_code': len(lines),
            }
            
            in_multiline = False
            in_docstring = False
            
            for line in lines:
                stripped = line.strip()
                
                if not stripped:
                    metrics['empty_lines'] += 1
                    continue
                
                # Docstring detekcija
                if stripped.startswith('"""') or stripped.startswith("'''"):
                    if not in_docstring:
                        in_docstring = True
                        metrics['docstrings'] += 1
                    else:
                        in_docstring = False
                    continue
                
                if in_docstring or in_multiline:
                    continue
                
                # TODO/FIXME/XXX
                lower = stripped.lower()
                if 'todo' in lower:
                    metrics['todo'] += 1
                if 'fixme' in lower:
                    metrics['fixme'] += 1
                if 'xxx' in lower:
                    metrics['xxx'] += 1
                
                # Komentari
                if '#' in line and not stripped.startswith('#'):
                    metrics['comments'] += 1
                
                # Regularni izrazi
                for key, pattern in cls.PATTERNS.items():
                    if re.search(pattern, line):
                        if key in ['if', 'elif', 'else', 'for', 'while', 'try', 'except', 'finally', 'with']:
                            metrics['control_structures'][key] += 1
                        elif key in metrics:
                            metrics[key] += 1
            
            # Izračunaj kompleksnost
            metrics['complexity_score'] = cls._calculate_complexity(metrics)
            metrics['cognitive_complexity'] = cls._calculate_cognitive(lines)
            metrics['maintainability_index'] = cls._calculate_maintainability(metrics, lines)
            metrics['complexity_level'] = cls._get_complexity_level(metrics['complexity_score'])
            
            return metrics
            
        except Exception as e:
            print(f"{Color.RED}✗ Greška pri analizi {file_path.name}: {e}{Color.RESET}")
            return None
    
    @staticmethod
    def _calculate_complexity(metrics):
        """Izračunava skor kompleksnosti"""
        score = 0
        score += metrics.get('classes', 0) * 3
        score += metrics.get('functions', 0) * 2
        score += metrics.get('async_functions', 0) * 2.5
        score += metrics.get('decorators', 0) * 1.5
        score += metrics.get('imports', 0) * 0.5
        
        cs = metrics.get('control_structures', {})
        score += cs.get('if', 0) * 1
        score += cs.get('elif', 0) * 1.2
        score += cs.get('else', 0) * 0.5
        score += cs.get('for', 0) * 1.5
        score += cs.get('while', 0) * 1.5
        score += cs.get('try', 0) * 2
        score += cs.get('except', 0) * 2
        score += cs.get('finally', 0) * 1
        score += cs.get('with', 0) * 1
        
        return round(score, 2)
    
    @staticmethod
    def _calculate_cognitive(lines):
        """Izračunava kognitivnu kompleksnost"""
        complexity = 0
        nesting = 0
        
        for line in lines:
            stripped = line.strip()
            
            if re.search(r'\b(if|for|while|except|with|def|class)\b', stripped):
                complexity += 1 + nesting
                nesting += 1
            elif stripped.startswith('else') or stripped.startswith('elif'):
                complexity += 1 + nesting
            elif stripped.startswith('except'):
                complexity += 1 + nesting
            elif nesting > 0 and not stripped:
                nesting -= 1
        
        return complexity
    
    @staticmethod
    def _calculate_maintainability(metrics, lines):
        """Izračunava indeks održavanja (0-100)"""
        total = len(lines)
        if total == 0:
            return 100.0
        
        volume = metrics.get('complexity_score', 1)
        cyclomatic = sum(metrics.get('control_structures', {}).values()) + 1
        
        try:
            mi = 171 - 5.2 * (volume ** 0.5) - 0.23 * cyclomatic - 16.2 * (total ** 0.5)
            return max(0, min(100, round(mi, 2)))
        except:
            return 50.0
    
    @staticmethod
    def _get_complexity_level(score):
        """Vraća nivo kompleksnosti sa bojom"""
        if score < 20:
            return f"{Color.GREEN}NISKA{Color.RESET}"
        elif score < 50:
            return f"{Color.YELLOW}SREDNJA{Color.RESET}"
        elif score < 100:
            return f"{Color.MAGENTA}VISOKA{Color.RESET}"
        else:
            return f"{Color.RED}KRITIČNA{Color.RESET}"


# ==============================================================================
# 🔍 PREMIUM DETEKTOR DUPLIH FAJLOVA
# ==============================================================================

class DuplicateFileDetector:
    """Napredna detekcija duplih i sličnih fajlova"""
    
    @staticmethod
    def calculate_hash(file_path, algorithm='md5'):
        """Izračunava hash fajla"""
        try:
            if algorithm == 'md5':
                hash_obj = hashlib.md5()
            elif algorithm == 'sha1':
                hash_obj = hashlib.sha1()
            elif algorithm == 'sha256':
                hash_obj = hashlib.sha256()
            else:
                hash_obj = hashlib.md5()
            
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    hash_obj.update(chunk)
            
            return hash_obj.hexdigest()
        except Exception:
            return None
    
    @classmethod
    def find_exact_duplicates(cls, files_data):
        """Pronalazi tačne duplikate (identičan sadržaj)"""
        hash_map = defaultdict(list)
        
        for f in files_data:
            if 'hash' in f and f['hash']:
                hash_map[f['hash']].append(f['rel_path'])
        
        duplicates = []
        for h, paths in hash_map.items():
            if len(paths) > 1:
                duplicates.append({
                    'hash': h[:8] + '...',
                    'files': paths,
                    'count': len(paths),
                    'size': sum(f['size'] for f in files_data if f['hash'] == h) / 1024
                })
        
        return sorted(duplicates, key=lambda x: x['count'], reverse=True)
    
    @classmethod
    def find_similar_files(cls, files_data, threshold=0.7, limit=50):
        """Pronalazi slične fajlove (Jaccard sličnost)"""
        if len(files_data) > limit:
            print(f"{Color.DIM}ℹ️  Ograničeno na {limit} fajlova za analizu sličnosti{Color.RESET}")
            files_data = files_data[:limit]
        
        contents = {}
        for f in files_data:
            try:
                with open(f['path'], 'r', encoding='utf-8') as file:
                    contents[f['rel_path']] = set(file.read().split())
            except Exception:
                pass
        
        similar = []
        paths = list(contents.keys())
        
        for i in range(len(paths)):
            for j in range(i + 1, len(paths)):
                set1, set2 = contents[paths[i]], contents[paths[j]]
                intersection = len(set1 & set2)
                union = len(set1 | set2)
                
                if union > 0:
                    similarity = intersection / union
                    if similarity > threshold:
                        similar.append({
                            'file1': paths[i],
                            'file2': paths[j],
                            'similarity': f"{similarity:.1%}"
                        })
        
        return sorted(similar, key=lambda x: x['similarity'], reverse=True)[:10]


# ==============================================================================
# 🔧 PREMIUM GIT INTEGRACIJA
# ==============================================================================

class GitStatsCollector:
    """Detaljna Git statistika za repozitorijum"""
    
    @staticmethod
    def is_git_repo(path):
        """Proverava da li je Git repozitorijum"""
        try:
            result = subprocess.run(
                ['git', 'rev-parse', '--git-dir'],
                cwd=path,
                capture_output=True,
                text=True,
                timeout=2
            )
            return result.returncode == 0
        except:
            return False
    
    @classmethod
    def collect(cls, path):
        """Prikuplja Git statistiku"""
        if not cls.is_git_repo(path):
            return None
        
        stats = {
            'total_commits': 0,
            'authors': [],
            'branches': 0,
            'tags': 0,
            'last_commit': {},
            'yearly_commits': 0,
            'monthly_commits': 0,
            'weekly_commits': 0,
            'total_additions': 0,
            'total_deletions': 0,
        }
        
        try:
            # Ukupno commitova
            result = subprocess.run(
                ['git', 'rev-list', '--count', '--all'],
                cwd=path,
                capture_output=True,
                text=True,
                timeout=2
            )
            stats['total_commits'] = int(result.stdout.strip() or 0)
            
            # Autori
            result = subprocess.run(
                ['git', 'shortlog', '-s', '-n', '--all'],
                cwd=path,
                capture_output=True,
                text=True,
                timeout=2
            )
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    parts = line.strip().split('\t')
                    if len(parts) == 2:
                        stats['authors'].append({
                            'commits': int(parts[0]),
                            'name': parts[1]
                        })
            
            # Poslednji commit
            result = subprocess.run(
                ['git', 'log', '-1', '--pretty=format:%h|%an|%ae|%s|%cr|%ct'],
                cwd=path,
                capture_output=True,
                text=True,
                timeout=2
            )
            parts = result.stdout.strip().split('|')
            if len(parts) >= 6:
                stats['last_commit'] = {
                    'hash': parts[0],
                    'author': parts[1],
                    'email': parts[2],
                    'message': parts[3],
                    'date': parts[4],
                    'timestamp': parts[5]
                }
            
            # Grane
            result = subprocess.run(
                ['git', 'branch', '-a'],
                cwd=path,
                capture_output=True,
                text=True,
                timeout=2
            )
            stats['branches'] = len([b for b in result.stdout.split('\n') if b.strip()])
            
            # Tagovi
            result = subprocess.run(
                ['git', 'tag'],
                cwd=path,
                capture_output=True,
                text=True,
                timeout=2
            )
            stats['tags'] = len([t for t in result.stdout.split('\n') if t.strip()])
            
            # Commitovi u poslednjih godinu dana
            result = subprocess.run(
                ['git', 'rev-list', '--count', '--since="1 year ago"', '--all'],
                cwd=path,
                capture_output=True,
                text=True,
                timeout=2
            )
            stats['yearly_commits'] = int(result.stdout.strip() or 0)
            
            # Commitovi u poslednjih mesec dana
            result = subprocess.run(
                ['git', 'rev-list', '--count', '--since="1 month ago"', '--all'],
                cwd=path,
                capture_output=True,
                text=True,
                timeout=2
            )
            stats['monthly_commits'] = int(result.stdout.strip() or 0)
            
            # Commitovi u poslednjih 7 dana
            result = subprocess.run(
                ['git', 'rev-list', '--count', '--since="7 days ago"', '--all'],
                cwd=path,
                capture_output=True,
                text=True,
                timeout=2
            )
            stats['weekly_commits'] = int(result.stdout.strip() or 0)
            
        except Exception as e:
            print(f"{Color.YELLOW}⚠️  Git greška: {e}{Color.RESET}")
            return None
        
        return stats


# ==============================================================================
# 📊 PREMIUM VIZUELIZACIJA - SPARKLINE, PROGRESS BAR, HISTOGRAM
# ==============================================================================

class PremiumVisualizer:
    """Vrhunska vizuelizacija podataka u terminalu"""
    
    # Unicode karakteri za grafike
    SPARK_CHARS = [" ", "▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"]
    PROGRESS_CHARS = [" ", "▏", "▎", "▍", "▌", "▋", "▊", "▉", "█"]
    PIE_CHARS = [" ", "◔", "◑", "◕", "●"]
    
    @classmethod
    def sparkline(cls, values, width=20, color=Color.CYAN):
        """Kreira sparkline grafikon"""
        if not values:
            return ""
        
        max_val = max(values) if values else 1
        min_val = min(values) if values else 0
        range_val = max_val - min_val if max_val > min_val else 1
        
        # Uzmi poslednjih 'width' vrednosti
        recent = values[-width:] if len(values) > width else values
        
        spark = ""
        for v in recent:
            normalized = (v - min_val) / range_val
            idx = min(8, int(normalized * 8))
            spark += cls.SPARK_CHARS[idx]
        
        return f"{color}{spark}{Color.RESET}"
    
    @classmethod
    def progress_bar(cls, value, max_value, width=30, label="", color=Color.GREEN, show_percent=True):
        """Kreira progress bar sa preciznim Unicode karakterima"""
        if max_value == 0:
            percent = 0
            filled = 0
        else:
            percent = value / max_value
            filled = int(width * percent)
        
        empty = width - filled
        
        # Precizni Unicode blokovi
        if filled == width:
            bar = f"{color}{'█' * width}{Color.RESET}"
        else:
            bar = f"{color}{'█' * filled}{Color.RESET}"
            
            if filled < width:
                remainder = int((percent * width - filled) * 8)
                if remainder > 0:
                    bar += f"{color}{cls.PROGRESS_CHARS[remainder]}{Color.RESET}"
                    empty -= 1
                bar += f"{Color.GRAY}{'░' * empty}{Color.RESET}"
        
        if label:
            output = f"{label} {bar}"
        else:
            output = bar
        
        if show_percent:
            output += f" {value:>6,} ({percent:>5.1%})"
        else:
            output += f" {value:>6,}"
        
        return output
    
    @classmethod
    def histogram(cls, data, bins=10, height=8, title="", color=Color.CYAN):
        """Kreira histogram distribucije"""
        if not data:
            return ""
        
        values = list(data.values()) if isinstance(data, dict) else data
        min_val = min(values)
        max_val = max(values)
        bin_width = (max_val - min_val) / bins if max_val > min_val else 1
        
        histogram = [0] * bins
        for v in values:
            idx = min(bins - 1, int((v - min_val) / bin_width) if bin_width > 0 else 0)
            histogram[idx] += 1
        
        max_count = max(histogram) if histogram else 1
        
        lines = []
        if title:
            lines.append(f"{Color.BOLD}{title}{Color.RESET}")
        
        # Crnaj histogram
        for level in range(height, 0, -1):
            line = "│"
            for count in histogram:
                bar_height = int((count / max_count) * height)
                if bar_height >= level:
                    line += f"{color}█{Color.RESET}"
                else:
                    line += " "
            lines.append(line)
        
        # X-osa
        lines.append("└" + "─" * bins)
        
        # Oznake
        labels = []
        for i in range(0, bins, max(1, bins // 5)):
            val = min_val + (i * bin_width)
            labels.append(f"{val:.0f}")
        
        label_line = " " + " ".join(labels)
        lines.append(label_line)
        
        return "\n".join(lines)
    
    @classmethod
    def pie_chart(cls, data, size=20, title=""):
        """Kreira jednostavan pie chart"""
        if not data:
            return ""
        
        total = sum(data.values())
        if total == 0:
            return ""
        
        lines = []
        if title:
            lines.append(f"{Color.BOLD}{title}{Color.RESET}")
        
        for label, value in data.items():
            percentage = value / total
            filled = int(percentage * size)
            
            if percentage >= 0.75:
                symbol = f"{Color.GREEN}{cls.PIE_CHARS[4]}{Color.RESET}"
            elif percentage >= 0.5:
                symbol = f"{Color.YELLOW}{cls.PIE_CHARS[3]}{Color.RESET}"
            elif percentage >= 0.25:
                symbol = f"{Color.MAGENTA}{cls.PIE_CHARS[2]}{Color.RESET}"
            else:
                symbol = f"{Color.RED}{cls.PIE_CHARS[1]}{Color.RESET}"
            
            bar = symbol * filled + " " * (size - filled)
            lines.append(f"  {bar}  {label:<15} {value:>6,} ({percentage:>5.1%})")
        
        return "\n".join(lines)


# ==============================================================================
# 📋 PERFEKTNO PORAVNATE TABELE - VRHUNSKI DIZAJN
# ==============================================================================

class PerfectTable:
    """Savršeno poravnate tabele sa Unicode okvirima i pametnim poravnanjem"""
    
    # Unicode karakteri za savršene okvire
    STYLE_MODERN = {
        'tl': '┌', 'tr': '┐', 'bl': '└', 'br': '┘',
        'h': '─', 'v': '│', 'tm': '┬', 'bm': '┴',
        'ml': '├', 'mr': '┤', 'c': '┼',
        'dh': '═', 'dv': '║'
    }
    
    STYLE_ROUND = {
        'tl': '╭', 'tr': '╮', 'bl': '╰', 'br': '╯',
        'h': '─', 'v': '│', 'tm': '┬', 'bm': '┴',
        'ml': '├', 'mr': '┤', 'c': '┼',
    }
    
    STYLE_DOUBLE = {
        'tl': '╔', 'tr': '╗', 'bl': '╚', 'br': '╝',
        'h': '═', 'v': '║', 'tm': '╦', 'bm': '╩',
        'ml': '╠', 'mr': '╣', 'c': '╬',
    }
    
    def __init__(self, style='modern'):
        self.style = self.STYLE_MODERN if style == 'modern' else \
                     self.STYLE_ROUND if style == 'round' else \
                     self.STYLE_DOUBLE
    
    @staticmethod
    def strip_colors(text):
        """Uklanja ANSI kodove za tačno merenje"""
        return re.sub(r'\033\[[0-9;]*m', '', str(text))
    
    @staticmethod
    def format_size(bytes_size):
        """Formatira veličinu fajla"""
        kb = bytes_size / 1024
        mb = bytes_size / (1024 * 1024)
        
        kb_str = f"{kb:.2f}" if kb >= 0.01 else "<0.01"
        mb_str = f"{mb:.3f}" if mb >= 0.001 else "<0.001"
        
        return kb_str, mb_str
    
    def create(self, headers, data, totals=None, title=None, max_col_widths=None):
        """Kreira perfektno poravnatu tabelu"""
        
        # Dodaj redne brojeve
        if headers[0] != "#":
            headers = ["#"] + headers
            for i, row in enumerate(data):
                data[i] = [str(i + 1)] + row
            if totals:
                totals = [""] + totals
        
        # Izračunaj širine kolona
        col_count = len(headers)
        col_widths = [0] * col_count
        
        all_rows = [headers] + data
        if totals:
            all_rows.append(totals)
        
        for row in all_rows:
            for i, cell in enumerate(row[:col_count]):
                clean = self.strip_colors(str(cell))
                col_widths[i] = max(col_widths[i], len(clean) + 2)  # +2 za padding
        
        # Primeni maksimalne širine
        if max_col_widths:
            for i, max_w in enumerate(max_col_widths[:col_count]):
                if max_w:
                    col_widths[i] = min(col_widths[i], max_w + 2)
        
        # Helper funkcije za okvire
        def top_border():
            return (self.style['tl'] + 
                    self.style['tm'].join(self.style['h'] * w for w in col_widths) + 
                    self.style['tr'])
        
        def mid_border():
            return (self.style['ml'] + 
                    self.style['c'].join(self.style['h'] * w for w in col_widths) + 
                    self.style['mr'])
        
        def bottom_border():
            return (self.style['bl'] + 
                    self.style['bm'].join(self.style['h'] * w for w in col_widths) + 
                    self.style['br'])
        
        def format_cell(cell, width, is_header=False, is_number=False, is_total=False):
            """Formatira ćeliju sa pametnim poravnanjem"""
            clean = self.strip_colors(str(cell))
            cell_len = len(clean)
            padding = width - cell_len - 2
            
            if is_header:
                # Centrirano
                left = padding // 2
                right = padding - left
                return f"{' ' * left} {cell} {' ' * right}"
            elif is_number or is_total:
                # Desno poravnanje
                return f"{' ' * padding} {cell} "
            else:
                # Levo poravnanje
                return f" {cell}{' ' * padding} "
        
        def format_row(row, is_header=False):
            """Formatira ceo red"""
            result = self.style['v']
            
            for i, cell in enumerate(row[:col_count]):
                width = col_widths[i]
                
                # Pametno poravnanje
                is_number = False
                if i > 0:  # Ne računajući redni broj
                    clean = self.strip_colors(str(cell))
                    try:
                        float(clean.replace(',', '').replace('<', ''))
                        is_number = True
                    except:
                        pass
                
                formatted = format_cell(
                    cell, width, 
                    is_header=is_header,
                    is_number=is_number,
                    is_total=(totals and row == totals)
                )
                result += formatted + self.style['v']
            
            return result
        
        # Kreiraj tabelu
        lines = []
        
        # Naslov
        if title:
            total_width = sum(col_widths) + len(col_widths) - 1
            clean_title = self.strip_colors(title)
            padding = total_width - len(clean_title) - 2
            
            lines.append("╔" + "═" * (total_width - 2) + "╗")
            lines.append(f"║{Color.BOLD}{Color.CYAN} {title} {' ' * padding}{Color.RESET}║")
            lines.append("╠" + "═" * (total_width - 2) + "╣")
        else:
            lines.append(top_border())
        
        # Zaglavlje
        lines.append(format_row(headers, is_header=True))
        lines.append(mid_border())
        
        # Podaci
        for i, row in enumerate(data):
            # Naizmenične boje za redove
            if i % 2 == 0:
                colored_row = []
                for j, cell in enumerate(row):
                    if j == 0:  # Redni broj
                        colored_row.append(f"{Color.GRAY}{cell}{Color.RESET}")
                    elif j == len(row) - 3:  # Linije
                        try:
                            num = int(self.strip_colors(str(cell)))
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
                    elif j == len(row) - 2:  # KB
                        colored_row.append(f"{Color.BLUE}{cell}{Color.RESET}")
                    elif j == len(row) - 1:  # MB
                        colored_row.append(f"{Color.MAGENTA}{cell}{Color.RESET}")
                    else:  # Putanja
                        colored_row.append(f"{Color.WHITE}{cell}{Color.RESET}")
                lines.append(format_row(colored_row))
            else:
                lines.append(format_row(row))
        
        # Ukupno
        if totals:
            lines.append(mid_border())
            colored_totals = []
            for j, cell in enumerate(totals):
                if j == 0:
                    colored_totals.append(f"{Color.BOLD}{cell}{Color.RESET}")
                elif j == len(totals) - 3:
                    colored_totals.append(f"{Color.BOLD}{Color.GREEN}{cell}{Color.RESET}")
                elif j == len(totals) - 2:
                    colored_totals.append(f"{Color.BOLD}{Color.BLUE}{cell}{Color.RESET}")
                elif j == len(totals) - 1:
                    colored_totals.append(f"{Color.BOLD}{Color.MAGENTA}{cell}{Color.RESET}")
                else:
                    colored_totals.append(f"{Color.BOLD}{cell}{Color.RESET}")
            lines.append(format_row(colored_totals))
        
        lines.append(bottom_border())
        
        return "\n".join(lines)


# ==============================================================================
# 📤 PREMIUM EXPORT - JSON, CSV, Markdown, HTML
# ==============================================================================

class PremiumExporter:
    """Multiformat export sa profesionalnim izgledom"""
    
    @staticmethod
    def to_json(files_data, output_file=None, include_stats=True):
        """Export u JSON format"""
        if not output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f"python_report_{timestamp}.json"
        
        report = {
            'generated': datetime.now().isoformat(),
            'generator': 'Python Line Counter Premium 2.0',
            'total_files': len(files_data),
            'total_lines': sum(f.get('lines', 0) for f in files_data),
            'total_size_bytes': sum(f.get('size', 0) for f in files_data),
            'total_size_kb': round(sum(f.get('size', 0) for f in files_data) / 1024, 2),
            'total_size_mb': round(sum(f.get('size', 0) for f in files_data) / (1024 * 1024), 3),
            'files': []
        }
        
        for f in files_data:
            file_entry = {
                'path': str(f.get('rel_path', '')),
                'name': f.get('name', ''),
                'lines': f.get('lines', 0),
                'size_bytes': f.get('size', 0),
                'size_kb': round(f.get('size', 0) / 1024, 2),
                'size_mb': round(f.get('size', 0) / (1024 * 1024), 3),
                'hash': f.get('hash', '')[:16] if f.get('hash') else ''
            }
            
            if 'complexity' in f and f['complexity']:
                file_entry['complexity'] = {
                    'score': f['complexity'].get('complexity_score', 0),
                    'level': PerfectTable.strip_colors(f['complexity'].get('complexity_level', '')),
                    'classes': f['complexity'].get('classes', 0),
                    'functions': f['complexity'].get('functions', 0),
                    'todo': f['complexity'].get('todo', 0),
                    'fixme': f['complexity'].get('fixme', 0)
                }
            
            report['files'].append(file_entry)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return output_file
    
    @staticmethod
    def to_csv(files_data, output_file=None):
        """Export u CSV format"""
        if not output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f"python_report_{timestamp}.csv"
        
        with open(output_file, 'w', newline='', encoding='utf-8-sig') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Redni broj', 'Putanja', 'Ime fajla', 
                'Linije', 'Veličina (B)', 'Veličina (KB)', 'Veličina (MB)',
                'Hash', 'Klase', 'Funkcije', 'TODO', 'FIXME', 'Kompleksnost'
            ])
            
            for i, f in enumerate(files_data, 1):
                kb = round(f.get('size', 0) / 1024, 2)
                mb = round(f.get('size', 0) / (1024 * 1024), 3)
                
                classes = f.get('complexity', {}).get('classes', 0) if 'complexity' in f else 0
                functions = f.get('complexity', {}).get('functions', 0) if 'complexity' in f else 0
                todo = f.get('complexity', {}).get('todo', 0) if 'complexity' in f else 0
                fixme = f.get('complexity', {}).get('fixme', 0) if 'complexity' in f else 0
                complexity = f.get('complexity', {}).get('complexity_score', 0) if 'complexity' in f else 0
                
                writer.writerow([
                    i, f.get('rel_path', ''), f.get('name', ''),
                    f.get('lines', 0), f.get('size', 0), kb, mb,
                    f.get('hash', '')[:8] if f.get('hash') else '',
                    classes, functions, todo, fixme, complexity
                ])
        
        return output_file
    
    @staticmethod
    def to_markdown(files_data, output_file=None):
        """Export u Markdown tabelu"""
        if not output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f"python_report_{timestamp}.md"
        
        total_lines = sum(f.get('lines', 0) for f in files_data)
        total_kb = round(sum(f.get('size', 0) for f in files_data) / 1024, 2)
        
        lines = []
        lines.append("# 📊 Python Line Counter - Premium Izveštaj\n")
        lines.append(f"*Generisano: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}*\n")
        
        lines.append("## 📁 Lista fajlova\n")
        lines.append("| # | Putanja | Linije | KB | MB |")
        lines.append("|---|---------|--------|-----|-----|")
        
        for i, f in enumerate(files_data[:100], 1):
            kb = round(f.get('size', 0) / 1024, 2)
            mb = round(f.get('size', 0) / (1024 * 1024), 3)
            path = f.get('rel_path', '')
            lines.append(f"| {i} | {path} | {f.get('lines', 0)} | {kb} | {mb} |")
        
        if len(files_data) > 100:
            lines.append(f"| ... | *još {len(files_data) - 100} fajlova* | | | |")
        
        lines.append("\n## 📊 Statistika\n")
        lines.append(f"- **Ukupno fajlova:** {len(files_data)}")
        lines.append(f"- **Ukupno linija:** {total_lines:,}")
        lines.append(f"- **Ukupna veličina:** {total_kb} KB")
        lines.append(f"- **Prosečno linija:** {round(total_lines / len(files_data), 1) if files_data else 0}")
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        
        return output_file
    
    @staticmethod
    def to_html(files_data, output_file=None):
        """Export u HTML sa modernim CSS"""
        if not output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f"python_report_{timestamp}.html"
        
        total_files = len(files_data)
        total_lines = sum(f.get('lines', 0) for f in files_data)
        total_kb = round(sum(f.get('size', 0) for f in files_data) / 1024, 2)
        total_mb = round(total_kb / 1024, 3)
        avg_lines = round(total_lines / total_files, 1) if total_files else 0
        
        # Generiši HTML redove
        table_rows = ""
        for i, f in enumerate(files_data[:200], 1):
            kb = round(f.get('size', 0) / 1024, 2)
            mb = round(f.get('size', 0) / (1024 * 1024), 3)
            
            # Boja za linije
            lines = f.get('lines', 0)
            if lines > 500:
                line_color = "#ff6b6b"
            elif lines > 200:
                line_color = "#feca57"
            elif lines > 50:
                line_color = "#48dbfb"
            else:
                line_color = "#a4b0be"
            
            table_rows += f"""
            <tr>
                <td>{i}</td>
                <td>{f.get('rel_path', '')}</td>
                <td style="color: {line_color}; font-weight: bold;">{lines}</td>
                <td>{kb}</td>
                <td>{mb}</td>
            </tr>"""
        
        if len(files_data) > 200:
            table_rows += f"""
            <tr>
                <td colspan="5" style="text-align: center; color: #666;">
                    ... i još {len(files_data) - 200} fajlova
                </td>
            </tr>"""
        
        html = f"""<!DOCTYPE html>
<html lang="sr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Python Line Counter - Premium Izveštaj</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 40px 20px;
            min-height: 100vh;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            padding: 30px;
        }}
        
        h1 {{
            color: #2d3748;
            font-size: 32px;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .date {{
            color: #718096;
            margin-bottom: 30px;
            font-size: 14px;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}
        
        .stat-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 10px 20px rgba(102, 126, 234, 0.3);
            transition: transform 0.3s;
        }}
        
        .stat-card:hover {{
            transform: translateY(-5px);
        }}
        
        .stat-value {{
            font-size: 36px;
            font-weight: 700;
            margin-bottom: 5px;
        }}
        
        .stat-label {{
            font-size: 14px;
            opacity: 0.9;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .table-container {{
            overflow-x: auto;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
        }}
        
        th {{
            background: #2d3748;
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
        }}
        
        td {{
            padding: 12px 15px;
            border-bottom: 1px solid #e2e8f0;
        }}
        
        tr:nth-child(even) {{
            background-color: #f7fafc;
        }}
        
        tr:hover {{
            background-color: #ebf4ff;
        }}
        
        .footer {{
            margin-top: 40px;
            text-align: center;
            color: #718096;
            font-size: 12px;
            border-top: 1px solid #e2e8f0;
            padding-top: 20px;
        }}
        
        .badge {{
            display: inline-block;
            padding: 5px 10px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            background: #48dbfb;
            color: #2d3748;
        }}
        
        @media (max-width: 768px) {{
            .container {{
                padding: 20px;
            }}
            
            .stat-value {{
                font-size: 28px;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>
            🐍 Python Line Counter Premium
            <span class="badge">v2.0</span>
        </h1>
        <div class="date">
            📅 Generisano: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')} • 
            📁 Analizirano: {total_files} fajlova
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{total_files:,}</div>
                <div class="stat-label">Python fajlova</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{total_lines:,}</div>
                <div class="stat-label">Ukupno linija</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{total_kb:,.1f}</div>
                <div class="stat-label">Kilobajta</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{total_mb:.3f}</div>
                <div class="stat-label">Megabajta</div>
            </div>
        </div>
        
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Putanja</th>
                        <th>Linije</th>
                        <th>KB</th>
                        <th>MB</th>
                    </tr>
                </thead>
                <tbody>
                    {table_rows}
                </tbody>
            </table>
        </div>
        
        <div class="footer">
            <p>⚡ Generisano pomoću Python Line Counter Premium • {datetime.now().strftime('%Y')}</p>
        </div>
    </div>
</body>
</html>"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)
        
        return output_file


# ==============================================================================
# 🏆 TOP LISTE - PREMIUM PRIKAZ
# ==============================================================================

class TopLists:
    """Premium prikaz top 10 listi"""
    
    @classmethod
    def display(cls, files_data):
        """Prikazuje sve top liste"""
        if not files_data:
            return
        
        print(f"\n{Color.BOLD}{Color.CYAN}🏆 TOP 10 LISTE - NAJBOLJI OD NAJBOLJIH{Color.RESET}")
        print("┌─────────────────────────────────────────────────────────────────┐")
        
        # Top 10 po linijama
        print(f"│ {Color.BOLD}📊 NAJVIŠE LINIJA KODA{Color.RESET}")
        by_lines = sorted(files_data, key=lambda x: x['lines'], reverse=True)[:10]
        
        for i, f in enumerate(by_lines, 1):
            path = f['rel_path']
            if len(path) > 45:
                path = path[:42] + "..."
            
            # Progress bar pored broja linija
            max_lines = by_lines[0]['lines'] if by_lines else 1
            bar = PremiumVisualizer.progress_bar(
                f['lines'], max_lines, 
                width=15, 
                color=Color.YELLOW,
                show_percent=False
            )
            
            print(f"│ {i:2}. {Color.YELLOW}{f['lines']:6,}{Color.RESET} linija  {path}")
            print(f"│     {bar}")
        
        print("├─────────────────────────────────────────────────────────────────┤")
        
        # Top 10 po veličini
        print(f"│ {Color.BOLD}💾 NAJVEĆI FAJLOVI NA DISKU{Color.RESET}")
        by_size = sorted(files_data, key=lambda x: x['size'], reverse=True)[:10]
        
        for i, f in enumerate(by_size, 1):
            path = f['rel_path']
            if len(path) > 45:
                path = path[:42] + "..."
            
            kb = f['size'] / 1024
            mb = f['size'] / (1024 * 1024)
            
            # Progress bar pored veličine
            max_size = by_size[0]['size'] if by_size else 1
            bar = PremiumVisualizer.progress_bar(
                f['size'], max_size, 
                width=15, 
                color=Color.BLUE,
                show_percent=False
            )
            
            print(f"│ {i:2}. {Color.BLUE}{kb:7.2f} KB{Color.RESET} ({mb:.3f} MB)  {path}")
            print(f"│     {bar}")
        
        print("├─────────────────────────────────────────────────────────────────┤")
        
        # Top 10 po kompleksnosti
        print(f"│ {Color.BOLD}🧠 NAJKOMPLEKSNIJI FAJLOVI{Color.RESET}")
        
        complex_files = [f for f in files_data if 'complexity' in f and f['complexity']]
        if complex_files:
            by_complexity = sorted(
                complex_files, 
                key=lambda x: x['complexity'].get('complexity_score', 0), 
                reverse=True
            )[:10]
            
            for i, f in enumerate(by_complexity, 1):
                path = f['rel_path']
                if len(path) > 45:
                    path = path[:42] + "..."
                
                score = f['complexity'].get('complexity_score', 0)
                level = PerfectTable.strip_colors(f['complexity'].get('complexity_level', ''))
                
                # Boja za nivo kompleksnosti
                if 'NISKA' in level:
                    level_color = Color.GREEN
                elif 'SREDNJA' in level:
                    level_color = Color.YELLOW
                elif 'VISOKA' in level:
                    level_color = Color.MAGENTA
                else:
                    level_color = Color.RED
                
                print(f"│ {i:2}. {Color.MAGENTA}{score:6.2f}{Color.RESET}  {level_color}{level:8}{Color.RESET}  {path}")
        else:
            print(f"│     {Color.GRAY}Nema podataka o kompleksnosti{Color.RESET}")
        
        print("├─────────────────────────────────────────────────────────────────┤")
        
        # Top 10 TODO/FIXME
        print(f"│ {Color.BOLD}⚠️  NAJVIŠE TODO/FIXME KOMENTARA{Color.RESET}")
        
        todo_files = []
        for f in files_data:
            if 'complexity' in f and f['complexity']:
                todo = f['complexity'].get('todo', 0) + f['complexity'].get('fixme', 0)
                if todo > 0:
                    todo_files.append((f, todo))
        
        if todo_files:
            by_todo = sorted(todo_files, key=lambda x: x[1], reverse=True)[:10]
            for i, (f, todo) in enumerate(by_todo, 1):
                path = f['rel_path']
                if len(path) > 45:
                    path = path[:42] + "..."
                print(f"│ {i:2}. {Color.YELLOW}{todo:4}{Color.RESET} komentara  {path}")
        else:
            print(f"│     {Color.GREEN}Nema TODO/FIXME komentara! Čist kod!{Color.RESET}")
        
        print("└─────────────────────────────────────────────────────────────────┘")


# ==============================================================================
# 👁️ LIVE PREVIEW - SAMO AKO JE WATCHDOG INSTALIRAN
# ==============================================================================

# Provera dostupnosti watchdog-a
WATCHDOG_AVAILABLE = importlib.util.find_spec("watchdog") is not None

if WATCHDOG_AVAILABLE:
    try:
        from watchdog.observers import Observer # type: ignore
        from watchdog.events import FileSystemEventHandler # type: ignore
        WATCHDOG_OK = True
    except ImportError:
        WATCHDOG_OK = False
else:
    WATCHDOG_OK = False

if WATCHDOG_OK:
    class PremiumLivePreviewHandler(FileSystemEventHandler):
        """Premium handler za live preview"""
        
        def __init__(self, callback):
            self.callback = callback
            self.last_trigger = 0
            self.debounce = Config.DEFAULT['live_preview_debounce']
            self.pending = False
        
        def on_modified(self, event):
            if not event.is_directory and event.src_path.endswith('.py'):
                self._trigger()
        
        def on_created(self, event):
            if not event.is_directory and event.src_path.endswith('.py'):
                self._trigger()
        
        def on_deleted(self, event):
            if not event.is_directory and event.src_path.endswith('.py'):
                self._trigger()
        
        def _trigger(self):
            now = time.time()
            if now - self.last_trigger > self.debounce:
                self.last_trigger = now
                self.pending = False
                self.callback()
            elif not self.pending:
                self.pending = True
                # Debounce timer
    
    class LivePreview:
        """Premium live preview sistem"""
        
        @staticmethod
        def start(directory, callback):
            """Pokreće live preview"""
            try:
                handler = PremiumLivePreviewHandler(callback)
                observer = Observer()
                observer.schedule(
                    handler, 
                    directory, 
                    recursive=Config.DEFAULT['live_preview_recursive']
                )
                observer.start()
                
                print(f"\n{Color.BOLD}{Color.BRIGHT_GREEN}👁️  LIVE PREVIEW MODE - AKTIVAN{Color.RESET}")
                print(f"{Color.CYAN}   📁 Pratim: {directory}{Color.RESET}")
                print(f"{Color.GRAY}   ⏱️  Debounce: {Config.DEFAULT['live_preview_debounce']}s{Color.RESET}")
                print(f"{Color.YELLOW}   ⚡ Pritisni Ctrl+C za zaustavljanje{Color.RESET}\n")
                
                return observer
            except Exception as e:
                print(f"{Color.RED}❌ Greška pri pokretanju live preview-a: {e}{Color.RESET}")
                return None
else:
    class LivePreview:
        @staticmethod
        def start(directory, callback):
            print(f"\n{Color.RED}❌ Live preview nije dostupan{Color.RESET}")
            print(f"{Color.YELLOW}   📦 Instaliraj watchdog: pip install watchdog{Color.RESET}")
            return None


# ==============================================================================
# 🎯 GLAVNI LINE COUNTER - SRCE PROGRAMA
# ==============================================================================

class PythonLineCounter:
    """Premium Python Line Counter sa svim funkcionalnostima"""
    
    def __init__(self, directory=".", config=None):
        self.directory = Path(directory).resolve()
        self.config = config or Config()
        self.cache = PremiumCache()
        self.files = []
        self.total_lines = 0
        self.total_size = 0
        self.start_time = None
        self.table_maker = PerfectTable(style='modern')
    
    def scan(self, use_cache=True, analyze_complexity=False):
        """Skenira direktorijum i analizira Python fajlove"""
        self.start_time = time.time()
        self.files = []
        self.total_lines = 0
        self.total_size = 0
        
        print(f"\n{Color.BOLD}{Color.BRIGHT_CYAN}╔════════════════════════════════════════════════════════════════╗{Color.RESET}")
        print(f"{Color.BOLD}{Color.BRIGHT_CYAN}║                    🔍 SKENIRANJE PYTHON FAJLOVA                    ║{Color.RESET}")
        print(f"{Color.BOLD}{Color.BRIGHT_CYAN}╚════════════════════════════════════════════════════════════════╝{Color.RESET}")
        print(f"{Color.CYAN}  📁 Direktorijum: {Color.WHITE}{self.directory}{Color.RESET}")
        print(f"{Color.CYAN}  ⏰ Vreme: {Color.WHITE}{datetime.now().strftime('%H:%M:%S %d.%m.%Y')}{Color.RESET}")
        
        ignore_patterns = self.config.get('ignore_patterns', [])
        file_count = 0
        
        for root, dirs, files in os.walk(self.directory):
            # Filtriraj direktorijume
            dirs[:] = [d for d in dirs if d not in ignore_patterns and not d.startswith('.')]
            
            for file in files:
                if file.endswith('.py'):
                    file_path = Path(root) / file
                    
                    try:
                        modified_time = file_path.stat().st_mtime
                        rel_path = file_path.relative_to(self.directory)
                        
                        # Proveri keš
                        cached = None
                        if use_cache and self.config.get('use_cache', True):
                            cached = self.cache.get(rel_path, modified_time)
                        
                        if cached:
                            lines = cached['lines']
                            file_size = cached['size']
                            file_hash = cached.get('hash', '')
                            complexity = None
                            
                            if analyze_complexity and 'complexity' in cached:
                                # Treba ponovo analizirati jer ne čuvamo ceo complexity objekat
                                complexity = CodeComplexityAnalyzer.analyze(file_path)
                        else:
                            # Čitaj fajl
                            with open(file_path, 'r', encoding='utf-8') as f:
                                lines = len(f.readlines())
                            
                            file_size = file_path.stat().st_size
                            file_hash = DuplicateFileDetector.calculate_hash(file_path)
                            
                            complexity = None
                            if analyze_complexity:
                                complexity = CodeComplexityAnalyzer.analyze(file_path)
                        
                        file_info = {
                            'path': file_path,
                            'rel_path': rel_path,
                            'name': file,
                            'lines': lines,
                            'size': file_size,
                            'modified': modified_time,
                            'hash': file_hash
                        }
                        
                        if complexity:
                            file_info['complexity'] = complexity
                            file_info['complexity_score'] = complexity.get('complexity_score', 0)
                        
                        self.files.append(file_info)
                        self.total_lines += lines
                        self.total_size += file_size
                        file_count += 1
                        
                        # Progress bar
                        if self.config.get('show_progress', True):
                            bar = PremiumVisualizer.progress_bar(
                                file_count, 
                                file_count + 1,  # Privremeno
                                width=30,
                                label=f"{Color.GREEN}✓{Color.RESET} Skenirano:",
                                color=Color.GREEN
                            )
                            sys.stdout.write(f"\r{bar}")
                            sys.stdout.flush()
                        
                    except Exception as e:
                        print(f"\n{Color.RED}✗ Greška: {file_path} - {e}{Color.RESET}")
        
        # Sačuvaj u keš
        if use_cache and self.files:
            self.cache.save(self.files, {
                'total_files': len(self.files),
                'total_lines': self.total_lines,
                'total_size': self.total_size
            })
        
        scan_time = time.time() - self.start_time
        print(f"\n{Color.GREEN}✅ Skeniranje završeno! {Color.DIM}({scan_time:.2f}s){Color.RESET}")
        print(f"{Color.CYAN}   📊 Pronađeno: {Color.WHITE}{file_count} Python fajlova{Color.RESET}")
        print(f"{Color.CYAN}   💾 Ukupna veličina: {Color.WHITE}{self.total_size / 1024:.2f} KB ({self.total_size / (1024*1024):.3f} MB){Color.RESET}")
        
        # Sortiranje
        sort_by = self.config.get('sort_by', 'path')
        reverse = self.config.get('sort_reverse', False)
        
        if sort_by == 'lines':
            self.files.sort(key=lambda x: x['lines'], reverse=reverse)
        elif sort_by == 'size':
            self.files.sort(key=lambda x: x['size'], reverse=reverse)
        elif sort_by == 'complexity':
            self.files.sort(key=lambda x: x.get('complexity_score', 0), reverse=reverse)
        else:
            self.files.sort(key=lambda x: str(x['rel_path']).lower(), reverse=reverse)
        
        return len(self.files)
    
    def display_results(self):
        """Prikazuje glavne rezultate u tabeli"""
        if not self.files:
            print(f"\n{Color.RED}❌ Nema Python fajlova za prikaz!{Color.RESET}")
            return
        
        # Pripremi podatke za tabelu
        table_data = []
        for f in self.files[:100]:  # Ograničeno na 100 za prikaz
            path = str(f['rel_path'])
            if len(path) > self.config.get('max_file_width', 45):
                path = "..." + path[-(self.config.get('max_file_width', 45)-3):]
            
            kb, mb = PerfectTable.format_size(f['size'])
            table_data.append([path, str(f['lines']), kb, mb])
        
        total_kb, total_mb = PerfectTable.format_size(self.total_size)
        totals = [f"{len(self.files)} fajlova", str(self.total_lines), total_kb, total_mb]
        
        title = f"📁 PYTHON FAJLOVI - {self.directory.name}"
        
        table = self.table_maker.create(
            headers=["FAJL", "LINIJA", "KB", "MB"],
            data=table_data,
            totals=totals,
            title=title,
            max_col_widths=[self.config.get('max_file_width', 45), None, 10, 10]
        )
        
        print(f"\n{table}")
        
        if len(self.files) > 100:
            print(f"{Color.DIM}   ... prikazano prvih 100 od {len(self.files)} fajlova{Color.RESET}")
        
        self._display_statistics()
    
    def _display_statistics(self):
        """Prikazuje detaljnu statistiku"""
        if not self.files:
            return
        
        total_files = len(self.files)
        avg_lines = self.total_lines / total_files if total_files > 0 else 0
        avg_size = self.total_size / total_files if total_files > 0 else 0
        avg_kb, avg_mb = PerfectTable.format_size(avg_size)
        total_kb, total_mb = PerfectTable.format_size(self.total_size)
        
        # Pronađi ekstreme
        largest_lines = max(self.files, key=lambda x: x['lines'])
        largest_size = max(self.files, key=lambda x: x['size'])
        smallest_lines = min(self.files, key=lambda x: x['lines'])
        smallest_size = min(self.files, key=lambda x: x['size'])
        
        print(f"\n{Color.BOLD}{Color.BRIGHT_CYAN}📊 STATISTIKA - DETALJNA ANALIZA{Color.RESET}")
        print("┌─────────────────────────────────────────────────────────────────┐")
        
        # Osnovna statistika
        print(f"│ {Color.BOLD}📈 OSNOVNI PODACI{Color.RESET}")
        print(f"│   • Ukupno fajlova:     {Color.YELLOW}{total_files:>8,}{Color.RESET}")
        print(f"│   • Ukupno linija:      {Color.YELLOW}{self.total_lines:>8,}{Color.RESET}")
        print(f"│   • Ukupna veličina:    {Color.YELLOW}{total_kb:>8} KB{Color.RESET} ({total_mb} MB)")
        print(f"│   • Prosečno linija:    {Color.YELLOW}{avg_lines:>8.1f}{Color.RESET}")
        print(f"│   • Prosečna veličina:  {Color.YELLOW}{avg_kb:>8} KB{Color.RESET} ({avg_mb} MB)")
        
        # Sparkline za distribuciju veličina
        if self.config.get('show_sparklines', True):
            sizes = [f['size'] / 1024 for f in self.files[:100]]  # Prvih 100
            spark = PremiumVisualizer.sparkline(sizes, width=50, color=Color.CYAN)
            print(f"│   • Trend veličina:     {spark} {Color.DIM}(KB){Color.RESET}")
        
        print("├─────────────────────────────────────────────────────────────────┤")
        
        # Ekstremi
        print(f"│ {Color.BOLD}🏆 REKORDERI{Color.RESET}")
        
        # Najviše linija
        name = largest_lines['name']
        if len(name) > 30:
            name = name[:27] + "..."
        print(f"│   • Najviše linija:     {Color.YELLOW}{largest_lines['lines']:>8,}{Color.RESET}  {Color.WHITE}{name}{Color.RESET}")
        
        # Najveći fajl
        name = largest_size['name']
        if len(name) > 30:
            name = name[:27] + "..."
        size_kb = largest_size['size'] / 1024
        print(f"│   • Najveći fajl:       {Color.BLUE}{size_kb:>8.2f} KB{Color.RESET}  {Color.WHITE}{name}{Color.RESET}")
        
        # Najmanje linija
        name = smallest_lines['name']
        if len(name) > 30:
            name = name[:27] + "..."
        print(f"│   • Najmanje linija:    {Color.GRAY}{smallest_lines['lines']:>8,}{Color.RESET}  {Color.WHITE}{name}{Color.RESET}")
        
        # Najmanji fajl
        name = smallest_size['name']
        if len(name) > 30:
            name = name[:27] + "..."
        size_kb = smallest_size['size'] / 1024
        print(f"│   • Najmanji fajl:      {Color.GRAY}{size_kb:>8.2f} KB{Color.RESET}  {Color.WHITE}{name}{Color.RESET}")
        
        # Performanse
        if self.start_time:
            scan_time = time.time() - self.start_time
            cache_stats = self.cache.get_stats()
            
            print("├─────────────────────────────────────────────────────────────────┤")
            print(f"│ {Color.BOLD}⚡ PERFORMANSE{Color.RESET}")
            print(f"│   • Vreme skeniranja:  {Color.CYAN}{scan_time:>8.2f} s{Color.RESET}")
            print(f"│   • Keširano fajlova:  {Color.CYAN}{cache_stats['files']:>8}{Color.RESET}")
            print(f"│   • Keš starost:       {Color.CYAN}{cache_stats['age'] / 60:>8.1f} min{Color.RESET}")
        
        print("└─────────────────────────────────────────────────────────────────┘")
    
    def display_directory_summary(self):
        """Prikazuje sumu po direktorijumima"""
        if not self.files:
            return
        
        dir_stats = {}
        for f in self.files:
            dir_path = str(Path(f['rel_path']).parent)
            if dir_path == '.':
                dir_path = '<root>'
            
            if dir_path not in dir_stats:
                dir_stats[dir_path] = {'files': 0, 'lines': 0, 'size': 0}
            
            dir_stats[dir_path]['files'] += 1
            dir_stats[dir_path]['lines'] += f['lines']
            dir_stats[dir_path]['size'] += f['size']
        
        # Sortiraj po linijama
        sorted_dirs = sorted(dir_stats.items(), key=lambda x: x[1]['lines'], reverse=True)
        
        # Pripremi podatke za tabelu
        table_data = []
        for dir_path, stats in sorted_dirs[:20]:
            path_display = dir_path
            if len(path_display) > 30:
                path_display = path_display[:27] + "..."
            
            kb, mb = PerfectTable.format_size(stats['size'])
            table_data.append([
                path_display,
                str(stats['files']),
                str(stats['lines']),
                kb,
                mb
            ])
        
        total_kb, total_mb = PerfectTable.format_size(self.total_size)
        totals = [
            "UKUPNO",
            str(len(self.files)),
            str(self.total_lines),
            total_kb,
            total_mb
        ]
        
        table = self.table_maker.create(
            headers=["DIREKTORIJUM", "FAJLOVI", "LINIJA", "KB", "MB"],
            data=table_data,
            totals=totals,
            title=f"{Color.CYAN}📂 DISTRIBUCIJA PO DIREKTORIJUMIMA{Color.RESET}",
            max_col_widths=[35, 8, 10, 10, 10]
        )
        
        print(f"\n{table}")
        
        if len(dir_stats) > 20:
            print(f"{Color.DIM}   ... prikazano 20 od {len(dir_stats)} direktorijuma{Color.RESET}")
    
    def display_complexity_analysis(self):
        """Prikazuje analizu kompleksnosti"""
        if not self.files:
            return
        
        complex_files = [f for f in self.files if 'complexity' in f and f['complexity']]
        if not complex_files:
            print(f"\n{Color.YELLOW}⚠️  Nema podataka o kompleksnosti. Pokreni sa --complexity flag-om.{Color.RESET}")
            return
        
        print(f"\n{Color.BOLD}{Color.BRIGHT_MAGENTA}🧠 ANALIZA KOMPLEKSNOSTI KODA{Color.RESET}")
        print("┌─────────────────────────────────────────────────────────────────┐")
        
        # Ukupna kompleksnost
        total_score = sum(f['complexity'].get('complexity_score', 0) for f in complex_files)
        avg_score = total_score / len(complex_files) if complex_files else 0
        
        print(f"│ {Color.BOLD}📊 STATISTIKA KOMPLEKSNOSTI{Color.RESET}")
        print(f"│   • Ukupni skor:        {Color.MAGENTA}{total_score:>8.2f}{Color.RESET}")
        print(f"│   • Prosečni skor:      {Color.MAGENTA}{avg_score:>8.2f}{Color.RESET}")
        print(f"│   • Analizirano:        {Color.CYAN}{len(complex_files):>8}{Color.RESET} fajlova")
        
        # Distribucija nivoa kompleksnosti
        levels = {'NISKA': 0, 'SREDNJA': 0, 'VISOKA': 0, 'KRITIČNA': 0}
        for f in complex_files:
            level = PerfectTable.strip_colors(f['complexity'].get('complexity_level', ''))
            if level in levels:
                levels[level] += 1
        
        print("├─────────────────────────────────────────────────────────────────┤")
        print(f"│ {Color.BOLD}📈 DISTRIBUCIJA NIVOA KOMPLEKSNOSTI{Color.RESET}")
        
        for level, count in levels.items():
            if count > 0:
                percentage = count / len(complex_files) * 100
                
                if level == 'NISKA':
                    color = Color.GREEN
                elif level == 'SREDNJA':
                    color = Color.YELLOW
                elif level == 'VISOKA':
                    color = Color.MAGENTA
                else:
                    color = Color.RED
                
                bar = PremiumVisualizer.progress_bar(
                    count, 
                    len(complex_files), 
                    width=30,
                    label=f"   • {level:9}",
                    color=color
                )
                print(f"│ {bar}")
        
        # TODO/FIXME statistika
        total_todo = sum(f['complexity'].get('todo', 0) for f in complex_files)
        total_fixme = sum(f['complexity'].get('fixme', 0) for f in complex_files)
        total_xxx = sum(f['complexity'].get('xxx', 0) for f in complex_files)
        
        if total_todo > 0 or total_fixme > 0:
            print("├─────────────────────────────────────────────────────────────────┤")
            print(f"│ {Color.BOLD}⚠️  KOMENTARI ZA PREGLED{Color.RESET}")
            print(f"│   • TODO:  {Color.YELLOW}{total_todo:>4}{Color.RESET}")
            print(f"│   • FIXME: {Color.YELLOW}{total_fixme:>4}{Color.RESET}")
            print(f"│   • XXX:   {Color.YELLOW}{total_xxx:>4}{Color.RESET}")
        
        # Najkompleksniji fajlovi
        print("├─────────────────────────────────────────────────────────────────┤")
        print(f"│ {Color.BOLD}🏆 NAJKOMPLEKSNIJI FAJLOVI (TOP 5){Color.RESET}")
        
        top_complex = sorted(
            complex_files, 
            key=lambda x: x['complexity'].get('complexity_score', 0), 
            reverse=True
        )[:5]
        
        for i, f in enumerate(top_complex, 1):
            path = str(f['rel_path'])
            if len(path) > 40:
                path = path[:37] + "..."
            
            score = f['complexity'].get('complexity_score', 0)
            level = PerfectTable.strip_colors(f['complexity'].get('complexity_level', ''))
            
            print(f"│   {i}. {Color.MAGENTA}{score:6.2f}{Color.RESET}  {level:8}  {Color.WHITE}{path}{Color.RESET}")
        
        print("└─────────────────────────────────────────────────────────────────┘")
    
    def display_duplicates(self):
        """Prikazuje duple fajlove"""
        duplicates = DuplicateFileDetector.find_exact_duplicates(self.files)
        
        if not duplicates:
            print(f"\n{Color.GREEN}✅ Nema duplih fajlova! Savršeno organizovano!{Color.RESET}")
            return
        
        print(f"\n{Color.BOLD}{Color.BRIGHT_YELLOW}🔄 DETEKTOVANI DUPLI FAJLOVI{Color.RESET}")
        print("┌─────────────────────────────────────────────────────────────────┐")
        print(f"│ {Color.BOLD}Pronađeno {len(duplicates)} grupa duplih fajlova{Color.RESET}")
        print("├─────────────────────────────────────────────────────────────────┤")
        
        for i, dup in enumerate(duplicates[:10], 1):
            print(f"│ {Color.BOLD}Grupa {i}:{Color.RESET} {Color.CYAN}{dup['hash']}{Color.RESET} ({dup['count']} kopije, {dup['size']:.1f} KB)")
            
            for j, path in enumerate(dup['files'][:3], 1):
                print(f"│   {j}. {path}")
            
            if len(dup['files']) > 3:
                print(f"│   ... i još {len(dup['files']) - 3} fajlova")
            
            if i < len(duplicates[:10]):
                print("├─────────────────────────────────────────────────────────────────┤")
        
        if len(duplicates) > 10:
            print("├─────────────────────────────────────────────────────────────────┤")
            print(f"│ ... i još {len(duplicates) - 10} grupa duplih fajlova")
        
        print("└─────────────────────────────────────────────────────────────────┘")
        
        # Potencijalna ušteda prostora
        total_duplicate_size = sum(dup['size'] * (dup['count'] - 1) for dup in duplicates)
        if total_duplicate_size > 0:
            print(f"{Color.CYAN}   💾 Potencijalna ušteda: {total_duplicate_size:.1f} KB ({total_duplicate_size/1024:.2f} MB){Color.RESET}")


# ==============================================================================
# 🚀 MAIN - GLAVNI POKRETAČ
# ==============================================================================

def main():
    """Glavna funkcija - ulazna tačka"""
    
    # Podesi Windows konzolu za boje
    if sys.platform == "win32":
        os.system("color")
    
    parser = argparse.ArgumentParser(
        description=f'''
{Color.BOLD}{Color.BRIGHT_CYAN}╔════════════════════════════════════════════════════════════════╗
║              🐍 PYTHON LINE COUNTER PREMIUM 2.0              ║
║         Savršeno poravnate tabele | Analiza | Export         ║
╚════════════════════════════════════════════════════════════════╝{Color.RESET}
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f'''
{Color.BRIGHT_GREEN}📌 PRIMERI UPOTREBE:{Color.RESET}
  python counter.py                    # Osnovno skeniranje
  python counter.py -a                 # Sve opcije (full analiza)
  python counter.py -c                # Analiza kompleksnosti
  python counter.py --top10           # Top 10 liste
  python counter.py --duplicates      # Pronađi duple fajlove
  python counter.py --git             # Git statistika
  python counter.py --live            # Live preview (zahteva watchdog)
  
{Color.BRIGHT_BLUE}📤 EXPORT FORMATI:{Color.RESET}
  python counter.py --export json     # JSON format
  python counter.py --export csv      # CSV format
  python counter.py --export md       # Markdown tabela
  python counter.py --export html     # HTML sa stilovima
  
{Color.BRIGHT_YELLOW}⚙️  SORTIRANJE:{Color.RESET}
  python counter.py --sort lines      # Sortiraj po linijama
  python counter.py --sort size       # Sortiraj po veličini
  python counter.py --sort complexity # Sortiraj po kompleksnosti
  python counter.py --reverse         # Obrnuti redosled
  
{Color.BRIGHT_MAGENTA}💾 KEŠ SISTEM:{Color.RESET}
  python counter.py --nocache         # Ignoriši keš
  python counter.py --reset-cache     # Resetuj keš memoriju
  python counter.py --cache-stats     # Prikaži statistiku keša
        '''
    )
    
    # Osnovni argumenti
    parser.add_argument('directory', nargs='?', default='.', 
                       help='Direktorijum za analizu (default: .)')
    
    # Opcije prikaza
    parser.add_argument('-a', '--all', action='store_true',
                       help='Prikaži sve opcije (full analiza)')
    parser.add_argument('-c', '--complexity', action='store_true',
                       help='Analiza kompleksnosti koda')
    parser.add_argument('-d', '--dirs', action='store_true',
                       help='Prikaži distribuciju po direktorijumima')
    parser.add_argument('--top10', action='store_true',
                       help='Prikaži top 10 liste')
    parser.add_argument('--duplicates', action='store_true',
                       help='Pronađi duple fajlove')
    parser.add_argument('--git', action='store_true',
                       help='Git statistika (ako je Git repozitorijum)')
    parser.add_argument('--live', action='store_true',
                       help='Live preview režim (zahteva watchdog)')
    
    # Export opcije
    parser.add_argument('--export', choices=['json', 'csv', 'md', 'html'],
                       help='Exportuj rezultate u zadati format')
    parser.add_argument('--output', 
                       help='Izlazni fajl za export (opciono)')
    
    # Sortiranje
    parser.add_argument('--sort', choices=['path', 'lines', 'size', 'complexity'],
                       default='path', help='Kriterijum sortiranja (default: path)')
    parser.add_argument('--reverse', action='store_true',
                       help='Obrnuti redosled sortiranja')
    
    # Keš opcije
    parser.add_argument('--nocache', action='store_true',
                       help='Ignoriši keš memoriju')
    parser.add_argument('--reset-cache', action='store_true',
                       help='Resetuj keš memoriju')
    parser.add_argument('--cache-stats', action='store_true',
                       help='Prikaži statistiku keša')
    
    # Konfiguracija
    parser.add_argument('--config', action='store_true',
                       help='Prikaži trenutnu konfiguraciju')
    parser.add_argument('--set-config', nargs=2, metavar=('KEY', 'VALUE'),
                       help='Postavi konfiguracionu vrednost')
    
    args = parser.parse_args()
    
    # Inicijalizacija konfiguracije
    config = Config()
    
    # ===== KONFIGURACIONE KOMANDE =====
    if args.config:
        print(f"\n{Color.BOLD}{Color.BRIGHT_CYAN}⚙️  TRENUTNA KONFIGURACIJA{Color.RESET}")
        print("┌─────────────────────────────────────────────────────────────────┐")
        
        for key, value in config.config.items():
            if isinstance(value, dict):
                print(f"│ {Color.YELLOW}{key:25}{Color.RESET} = {Color.WHITE}{json.dumps(value, ensure_ascii=False)[:50]}{Color.RESET}")
            else:
                print(f"│ {Color.YELLOW}{key:25}{Color.RESET} = {Color.WHITE}{value}{Color.RESET}")
        
        print("└─────────────────────────────────────────────────────────────────┘")
        return
    
    if args.set_config:
        key, value = args.set_config
        
        # Pokušaj konverzije tipa
        try:
            if value.lower() == 'true':
                value = True
            elif value.lower() == 'false':
                value = False
            elif value.isdigit():
                value = int(value)
            elif value.replace('.', '', 1).isdigit():
                value = float(value)
            elif value.startswith('[') and value.endswith(']'):
                value = json.loads(value)
        except:
            pass
        
        config.set(key, value)
        print(f"{Color.GREEN}✅ Konfiguracija ažurirana: {key} = {value}{Color.RESET}")
        return
    
    if args.cache_stats:
        cache = PremiumCache()
        stats = cache.get_stats()
        
        print(f"\n{Color.BOLD}{Color.BRIGHT_CYAN}💾 STATISTIKA KEŠ MEMORIJE{Color.RESET}")
        print("┌─────────────────────────────────────────────────────────────────┐")
        print(f"│   • Keširani fajlovi:  {Color.YELLOW}{stats['files']:>8}{Color.RESET}")
        print(f"│   • Hash indeks:       {Color.YELLOW}{stats['hashes']:>8}{Color.RESET}")
        print(f"│   • Starost keša:      {Color.CYAN}{stats['age'] / 60:>8.1f} min{Color.RESET}")
        print(f"│   • Verzija:           {Color.GRAY}{stats['version']}{Color.RESET}")
        print("└─────────────────────────────────────────────────────────────────┘")
        return
    
    # ===== RESET KEŠA =====
    if args.reset_cache:
        cache = PremiumCache()
        cache.invalidate()
        return
    
    # ===== POSTAVI SORTIRANJE =====
    if args.sort:
        config.set('sort_by', args.sort)
    if args.reverse:
        config.set('sort_reverse', True)
    
    # ===== PROVERI DIREKTORIJUM =====
    if not os.path.isdir(args.directory):
        print(f"{Color.RED}❌ Direktorijum '{args.directory}' ne postoji!{Color.RESET}")
        return
    
    # ===== KREIRAJ COUNTER =====
    counter = PythonLineCounter(args.directory, config)
    
    # ===== LIVE PREVIEW =====
    if args.live:
        if not WATCHDOG_OK:
            print(f"\n{Color.RED}❌ Live preview nije dostupan!{Color.RESET}")
            print(f"{Color.YELLOW}   📦 Instaliraj watchdog: pip install watchdog{Color.RESET}")
            return
        
        def refresh_callback():
            counter.scan(
                use_cache=not args.nocache,
                analyze_complexity=(args.complexity or args.all)
            )
            counter.display_results()
            
            if args.dirs or args.all:
                counter.display_directory_summary()
        
        observer = LivePreview.start(args.directory, refresh_callback)
        
        if observer:
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print(f"\n{Color.YELLOW}⏹️  Live preview zaustavljen{Color.RESET}")
                observer.stop()
                observer.join()
        
        return
    
    # ===== NORMALNO SKENIRANJE =====
    try:
        analyze_complexity = args.complexity or args.all or args.top10 or args.duplicates
        
        # Skeniraj
        counter.scan(
            use_cache=not args.nocache,
            analyze_complexity=analyze_complexity
        )
        
        if not counter.files:
            print(f"\n{Color.YELLOW}ℹ️  Nema Python fajlova za prikaz.{Color.RESET}")
            return
        
        # Prikaži rezultate
        print(f"\n{Color.GREEN}{'═' * 70}{Color.RESET}")
        counter.display_results()
        
        # Dodatne opcije
        if args.dirs or args.all:
            counter.display_directory_summary()
        
        if args.complexity or args.all:
            counter.display_complexity_analysis()
        
        if args.top10 or args.all:
            TopLists.display(counter.files)
        
        if args.duplicates or args.all:
            counter.display_duplicates()
        
        if args.git or args.all:
            git_stats = GitStatsCollector.collect(args.directory)
            if git_stats:
                print(f"\n{Color.BOLD}{Color.BRIGHT_CYAN}🔧 GIT STATISTIKA REPOZITORIJUMA{Color.RESET}")
                print("┌─────────────────────────────────────────────────────────────────┐")
                print(f"│   • Ukupno commitova:  {Color.YELLOW}{git_stats['total_commits']:>8,}{Color.RESET}")
                print(f"│   • Broj autora:       {Color.YELLOW}{len(git_stats['authors']):>8}{Color.RESET}")
                print(f"│   • Broj grana:        {Color.YELLOW}{git_stats['branches']:>8}{Color.RESET}")
                print(f"│   • Broj tagova:       {Color.YELLOW}{git_stats['tags']:>8}{Color.RESET}")
                print(f"│   • Commitovi (1g):    {Color.CYAN}{git_stats['yearly_commits']:>8}{Color.RESET}")
                print(f"│   • Commitovi (1m):    {Color.CYAN}{git_stats['monthly_commits']:>8}{Color.RESET}")
                print(f"│   • Commitovi (7d):    {Color.CYAN}{git_stats['weekly_commits']:>8}{Color.RESET}")
                
                if 'last_commit' in git_stats:
                    lc = git_stats['last_commit']
                    print("├─────────────────────────────────────────────────────────────────┤")
                    print(f"│ {Color.BOLD}📌 POSLEDNJI COMMIT{Color.RESET}")
                    print(f"│   • Hash:    {Color.CYAN}{lc['hash']}{Color.RESET}")
                    print(f"│   • Autor:   {Color.WHITE}{lc['author']}{Color.RESET} <{lc['email']}>")
                    print(f"│   • Poruka:  {Color.WHITE}{lc['message'][:50]}{Color.RESET}")
                    print(f"│   • Pre:     {Color.GRAY}{lc['date']}{Color.RESET}")
                
                print("└─────────────────────────────────────────────────────────────────┘")
            else:
                print(f"\n{Color.YELLOW}ℹ️  Nije Git repozitorijum ili Git nije instaliran{Color.RESET}")
        
        # ===== EXPORT =====
        if args.export:
            exporter = PremiumExporter()
            output_file = args.output
            
            try:
                if args.export == 'json':
                    output_file = exporter.to_json(counter.files, output_file)
                elif args.export == 'csv':
                    output_file = exporter.to_csv(counter.files, output_file)
                elif args.export == 'md':
                    output_file = exporter.to_markdown(counter.files, output_file)
                elif args.export == 'html':
                    output_file = exporter.to_html(counter.files, output_file)
                
                print(f"\n{Color.GREEN}✅ Export uspešan!{Color.RESET}")
                print(f"{Color.CYAN}   📁 Fajl: {Color.WHITE}{output_file}{Color.RESET}")
                
                # Veličina exportovanog fajla
                if os.path.exists(output_file):
                    size_kb = os.path.getsize(output_file) / 1024
                    print(f"{Color.CYAN}   💾 Veličina: {Color.WHITE}{size_kb:.2f} KB{Color.RESET}")
                    
            except Exception as e:
                print(f"\n{Color.RED}❌ Greška pri exportu: {e}{Color.RESET}")
        
        # ===== ZAVRŠETAK =====
        print(f"\n{Color.BOLD}{Color.BRIGHT_GREEN}✅ ANALIZA USPEŠNO ZAVRŠENA{Color.RESET}")
        
        cache_stats = counter.cache.get_stats()
        if cache_stats['files'] > 0:
            print(f"{Color.DIM}   💾 Keš: {cache_stats['files']} fajlova, {cache_stats['age'] / 60:.1f} min starosti{Color.RESET}")
        
    except KeyboardInterrupt:
        print(f"\n\n{Color.YELLOW}⏹️  Prekinuto od strane korisnika{Color.RESET}")
    except Exception as e:
        print(f"\n{Color.RED}❌ Neočekivana greška: {e}{Color.RESET}")
        
        if os.environ.get('DEBUG'):
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    main()