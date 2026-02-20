"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║   🐍 PYTHON LINE COUNTER PREMIUM 2.0 - SA VRHUNSKIM DIZAJNOM                 ║
║   Savršeno poravnate tabele | Analiza kompleksnosti | Live Preview          ║
║   Git integracija | Dupli fajlovi | Export | Vizuelizacija                  ║
║   🏆 TOP 10 REKORDERI | Medalje | Progress barovi | Statistika              ║
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
        'sort_by': 'path',
        'sort_reverse': False,
        
        # Ignorisanje
        'ignore_patterns': [
            'venv', '.venv', 'env', '.env', 
            '.git', '__pycache__', '.idea', '.vscode',
            'node_modules', 'dist', 'build', '*.pyc',
            '.pytest_cache', '.mypy_cache', '.coverage'
        ],
        
        # Keš
        'cache_timeout': 3600,
        'use_cache': True,
        
        # Pragovi
        'large_file_threshold': 500,
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
# 💾 PREMIUM CACHE SISTEM
# ==============================================================================

class PremiumCache:
    """Napredni keš sistem sa MD5 hash indeksiranjem"""
    
    def __init__(self, cache_file=".pycounter_cache.json"):
        self.cache_file = cache_file
        self.cache = self._load()
    
    def _load(self):
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r', encoding='utf-8') as f:
                    cache = json.load(f)
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
        key = str(file_path)
        cached = self.cache.get('files', {}).get(key)
        if cached and cached.get('modified', 0) == modified_time:
            return cached
        return None
    
    def invalidate(self):
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
        return {
            'files': len(self.cache.get('files', {})),
            'hashes': len(self.cache.get('hash_index', {})),
            'age': time.time() - self.cache.get('timestamp', 0),
            'version': self.cache.get('version', 'unknown')
        }


# ==============================================================================
# 🧠 ANALIZA KOMPLEKSNOSTI KODA
# ==============================================================================

class CodeComplexityAnalyzer:
    """Sveobuhvatna analiza Python koda"""
    
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
    }
    
    @classmethod
    def analyze(cls, file_path):
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
            
            in_docstring = False
            
            for line in lines:
                stripped = line.strip()
                
                if not stripped:
                    metrics['empty_lines'] += 1
                    continue
                
                if stripped.startswith('"""') or stripped.startswith("'''"):
                    in_docstring = not in_docstring
                    if not in_docstring:
                        metrics['docstrings'] += 1
                    continue
                
                if in_docstring:
                    continue
                
                lower = stripped.lower()
                if 'todo' in lower:
                    metrics['todo'] += 1
                if 'fixme' in lower:
                    metrics['fixme'] += 1
                if 'xxx' in lower:
                    metrics['xxx'] += 1
                
                if '#' in line and not stripped.startswith('#'):
                    metrics['comments'] += 1
                
                for key, pattern in cls.PATTERNS.items():
                    if re.search(pattern, line):
                        if key in ['if', 'elif', 'else', 'for', 'while', 'try', 'except', 'finally', 'with']:
                            metrics['control_structures'][key] += 1
                        elif key in metrics:
                            metrics[key] += 1
            
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
        complexity = 0
        nesting = 0
        for line in lines:
            stripped = line.strip()
            if re.search(r'\b(if|for|while|except|with|def|class)\b', stripped):
                complexity += 1 + nesting
                nesting += 1
            elif stripped.startswith(('else', 'elif', 'except')):
                complexity += 1 + nesting
            elif nesting > 0 and not stripped:
                nesting -= 1
        return complexity
    
    @staticmethod
    def _calculate_maintainability(metrics, lines):
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
        if score < 20:
            return f"{Color.GREEN}NISKA{Color.RESET}"
        elif score < 50:
            return f"{Color.YELLOW}SREDNJA{Color.RESET}"
        elif score < 100:
            return f"{Color.MAGENTA}VISOKA{Color.RESET}"
        else:
            return f"{Color.RED}KRITIČNA{Color.RESET}"


# ==============================================================================
# 🔍 DETEKTOR DUPLIH FAJLOVA
# ==============================================================================

class DuplicateFileDetector:
    """Detekcija duplih fajlova"""
    
    @staticmethod
    def calculate_hash(file_path):
        try:
            hash_md5 = hashlib.md5()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception:
            return None
    
    @classmethod
    def find_exact_duplicates(cls, files_data):
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


# ==============================================================================
# 🔧 GIT INTEGRACIJA
# ==============================================================================

class GitStatsCollector:
    """Git statistika"""
    
    @staticmethod
    def is_git_repo(path):
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
        }
        
        try:
            result = subprocess.run(
                ['git', 'rev-list', '--count', '--all'],
                cwd=path,
                capture_output=True,
                text=True,
                timeout=2
            )
            stats['total_commits'] = int(result.stdout.strip() or 0)
            
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
            
            result = subprocess.run(
                ['git', 'log', '-1', '--pretty=format:%h|%an|%ae|%s|%cr'],
                cwd=path,
                capture_output=True,
                text=True,
                timeout=2
            )
            parts = result.stdout.strip().split('|')
            if len(parts) >= 5:
                stats['last_commit'] = {
                    'hash': parts[0],
                    'author': parts[1],
                    'email': parts[2],
                    'message': parts[3],
                    'date': parts[4]
                }
            
            result = subprocess.run(
                ['git', 'branch', '-a'],
                cwd=path,
                capture_output=True,
                text=True,
                timeout=2
            )
            stats['branches'] = len([b for b in result.stdout.split('\n') if b.strip()])
            
            result = subprocess.run(
                ['git', 'tag'],
                cwd=path,
                capture_output=True,
                text=True,
                timeout=2
            )
            stats['tags'] = len([t for t in result.stdout.split('\n') if t.strip()])
            
            for period, flag in [('yearly', '1 year'), ('monthly', '1 month'), ('weekly', '7 days')]:
                result = subprocess.run(
                    ['git', 'rev-list', '--count', f'--since="{flag} ago"', '--all'],
                    cwd=path,
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                stats[f'{period}_commits'] = int(result.stdout.strip() or 0)
            
        except Exception:
            return None
        
        return stats


# ==============================================================================
# 📊 PREMIUM VIZUELIZACIJA
# ==============================================================================

class PremiumVisualizer:
    """Vrhunska vizuelizacija podataka u terminalu"""
    
    SPARK_CHARS = [" ", "▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"]
    PROGRESS_CHARS = [" ", "▏", "▎", "▍", "▌", "▋", "▊", "▉", "█"]
    
    @classmethod
    def sparkline(cls, values, width=20, color=Color.CYAN):
        if not values:
            return ""
        max_val = max(values) if values else 1
        min_val = min(values) if values else 0
        range_val = max_val - min_val if max_val > min_val else 1
        recent = values[-width:] if len(values) > width else values
        spark = ""
        for v in recent:
            normalized = (v - min_val) / range_val
            idx = min(8, int(normalized * 8))
            spark += cls.SPARK_CHARS[idx]
        return f"{color}{spark}{Color.RESET}"
    
    @classmethod
    def progress_bar(cls, value, max_value, width=30, label="", color=Color.GREEN, show_percent=True):
        if max_value == 0:
            percent = 0
            filled = 0
        else:
            percent = value / max_value
            filled = int(width * percent)
        
        empty = width - filled
        
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
        
        output = f"{label} {bar}" if label else bar
        if show_percent:
            output += f" {value:>6,} ({percent:>5.1%})"
        else:
            output += f" {value:>6,}"
        return output


# ==============================================================================
# 📋 PERFEKTNO PORAVNATE TABELE
# ==============================================================================

class PerfectTable:
    """Savršeno poravnate tabele sa Unicode okvirima"""
    
    STYLE_MODERN = {
        'tl': '┌', 'tr': '┐', 'bl': '└', 'br': '┘',
        'h': '─', 'v': '│', 'tm': '┬', 'bm': '┴',
        'ml': '├', 'mr': '┤', 'c': '┼'
    }
    
    STYLE_DOUBLE = {
        'tl': '╔', 'tr': '╗', 'bl': '╚', 'br': '╝',
        'h': '═', 'v': '║', 'tm': '╦', 'bm': '╩',
        'ml': '╠', 'mr': '╣', 'c': '╬'
    }
    
    def __init__(self, style='modern'):
        self.style = self.STYLE_MODERN if style == 'modern' else self.STYLE_DOUBLE
    
    @staticmethod
    def strip_colors(text):
        return re.sub(r'\033\[[0-9;]*m', '', str(text))
    
    @staticmethod
    def format_size(bytes_size):
        kb = bytes_size / 1024
        mb = bytes_size / (1024 * 1024)
        kb_str = f"{kb:.2f}" if kb >= 0.01 else "<0.01"
        mb_str = f"{mb:.3f}" if mb >= 0.001 else "<0.001"
        return kb_str, mb_str
    
    def create(self, headers, data, totals=None, title=None, max_col_widths=None):
        if headers[0] != "#":
            headers = ["#"] + headers
            for i, row in enumerate(data):
                data[i] = [str(i + 1)] + row
            if totals:
                totals = [""] + totals
        
        col_count = len(headers)
        col_widths = [0] * col_count
        
        all_rows = [headers] + data
        if totals:
            all_rows.append(totals)
        
        for row in all_rows:
            for i, cell in enumerate(row[:col_count]):
                clean = self.strip_colors(str(cell))
                col_widths[i] = max(col_widths[i], len(clean) + 2)
        
        if max_col_widths:
            for i, max_w in enumerate(max_col_widths[:col_count]):
                if max_w:
                    col_widths[i] = min(col_widths[i], max_w + 2)
        
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
        
        def format_cell(cell, width, is_header=False, is_number=False):
            clean = self.strip_colors(str(cell))
            cell_len = len(clean)
            padding = width - cell_len - 2
            
            if is_header:
                left = padding // 2
                right = padding - left
                return f"{' ' * left} {cell} {' ' * right}"
            elif is_number:
                return f"{' ' * padding} {cell} "
            else:
                return f" {cell}{' ' * padding} "
        
        def format_row(row, is_header=False):
            result = self.style['v']
            for i, cell in enumerate(row[:col_count]):
                width = col_widths[i]
                is_number = False
                if i > 0:
                    clean = self.strip_colors(str(cell))
                    try:
                        float(clean.replace(',', '').replace('<', ''))
                        is_number = True
                    except:
                        pass
                formatted = format_cell(cell, width, is_header, is_number)
                result += formatted + self.style['v']
            return result
        
        lines = []
        
        if title:
            total_width = sum(col_widths) + len(col_widths) - 1
            clean_title = self.strip_colors(title)
            padding = total_width - len(clean_title) - 2
            lines.append("╔" + "═" * (total_width - 2) + "╗")
            lines.append(f"║{Color.BOLD}{Color.CYAN} {title} {' ' * padding}{Color.RESET}║")
            lines.append("╠" + "═" * (total_width - 2) + "╣")
        else:
            lines.append(top_border())
        
        lines.append(format_row(headers, is_header=True))
        lines.append(mid_border())
        
        for i, row in enumerate(data):
            if i % 2 == 0:
                colored_row = []
                for j, cell in enumerate(row):
                    if j == 0:
                        colored_row.append(f"{Color.GRAY}{cell}{Color.RESET}")
                    elif j == len(row) - 3:
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
                    elif j == len(row) - 2:
                        colored_row.append(f"{Color.BLUE}{cell}{Color.RESET}")
                    elif j == len(row) - 1:
                        colored_row.append(f"{Color.MAGENTA}{cell}{Color.RESET}")
                    else:
                        colored_row.append(f"{Color.WHITE}{cell}{Color.RESET}")
                lines.append(format_row(colored_row))
            else:
                lines.append(format_row(row))
        
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
# 📤 PREMIUM EXPORT
# ==============================================================================

class PremiumExporter:
    """Multiformat export"""
    
    @staticmethod
    def to_json(files_data, output_file=None):
        if not output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f"python_report_{timestamp}.json"
        
        report = {
            'generated': datetime.now().isoformat(),
            'generator': 'Python Line Counter Premium 2.0',
            'total_files': len(files_data),
            'total_lines': sum(f.get('lines', 0) for f in files_data),
            'total_size_kb': round(sum(f.get('size', 0) for f in files_data) / 1024, 2),
            'total_size_mb': round(sum(f.get('size', 0) for f in files_data) / (1024 * 1024), 3),
            'files': []
        }
        
        for f in files_data:
            file_entry = {
                'path': str(f.get('rel_path', '')),
                'lines': f.get('lines', 0),
                'size_kb': round(f.get('size', 0) / 1024, 2),
                'size_mb': round(f.get('size', 0) / (1024 * 1024), 3),
                'hash': f.get('hash', '')[:8] if f.get('hash') else ''
            }
            if 'complexity' in f and f['complexity']:
                file_entry['complexity'] = {
                    'score': f['complexity'].get('complexity_score', 0),
                    'level': PerfectTable.strip_colors(f['complexity'].get('complexity_level', '')),
                }
            report['files'].append(file_entry)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        return output_file
    
    @staticmethod
    def to_csv(files_data, output_file=None):
        if not output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f"python_report_{timestamp}.csv"
        
        with open(output_file, 'w', newline='', encoding='utf-8-sig') as f:
            writer = csv.writer(f)
            writer.writerow(['Redni broj', 'Putanja', 'Linije', 'KB', 'MB', 'Hash'])
            
            for i, f in enumerate(files_data, 1):
                kb = round(f.get('size', 0) / 1024, 2)
                mb = round(f.get('size', 0) / (1024 * 1024), 3)
                writer.writerow([
                    i, f.get('rel_path', ''), f.get('lines', 0),
                    kb, mb, f.get('hash', '')[:8] if f.get('hash') else ''
                ])
        return output_file
    
    @staticmethod
    def to_html(files_data, output_file=None):
        if not output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f"python_report_{timestamp}.html"
        
        total_files = len(files_data)
        total_lines = sum(f.get('lines', 0) for f in files_data)
        total_kb = round(sum(f.get('size', 0) for f in files_data) / 1024, 2)
        
        top_10 = sorted(files_data, key=lambda x: x['lines'], reverse=True)[:10]
        
        table_rows = ""
        for i, f in enumerate(top_10, 1):
            kb = round(f.get('size', 0) / 1024, 2)
            mb = round(f.get('size', 0) / (1024 * 1024), 3)
            lines = f.get('lines', 0)
            
            medal = ""
            if i == 1:
                medal = "🥇"
            elif i == 2:
                medal = "🥈"
            elif i == 3:
                medal = "🥉"
            
            table_rows += f"""
            <tr>
                <td><strong>{medal} {i}</strong></td>
                <td>{f.get('rel_path', '')}</td>
                <td style="color: {'#ff6b6b' if lines > 500 else '#feca57' if lines > 200 else '#48dbfb'}; font-weight: bold;">{lines}</td>
                <td>{kb}</td>
                <td>{mb}</td>
            </tr>"""
        
        html = f"""<!DOCTYPE html>
<html lang="sr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Python Line Counter - Premium Izveštaj</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');
        body {{ font-family: 'Inter', sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 40px 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; border-radius: 20px; padding: 30px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); }}
        h1 {{ color: #2d3748; display: flex; align-items: center; gap: 10px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 30px; }}
        .stat-card {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 15px; }}
        .stat-value {{ font-size: 32px; font-weight: 700; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th {{ background: #2d3748; color: white; padding: 12px; }}
        td {{ padding: 10px; border-bottom: 1px solid #e2e8f0; }}
        tr:nth-child(even) {{ background: #f7fafc; }}
        .medal {{ font-size: 20px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🐍 Python Line Counter Premium <span style="background: #48dbfb; padding: 5px 10px; border-radius: 20px; font-size: 14px;">v2.0</span></h1>
        <p>📅 Generisano: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}</p>
        
        <div class="stats-grid">
            <div class="stat-card"><div class="stat-value">{total_files}</div><div>Python fajlova</div></div>
            <div class="stat-card"><div class="stat-value">{total_lines:,}</div><div>Ukupno linija</div></div>
            <div class="stat-card"><div class="stat-value">{total_kb:.1f}</div><div>Kilobajta</div></div>
            <div class="stat-card"><div class="stat-value">{(total_kb/1024):.3f}</div><div>Megabajta</div></div>
        </div>
        
        <h2>🏆 TOP 10 REKORDERI - NAJVIŠE LINIJA</h2>
        <table>
            <thead><tr><th>#</th><th>Putanja</th><th>Linije</th><th>KB</th><th>MB</th></tr></thead>
            <tbody>{table_rows}</tbody>
        </table>
        <p style="color: #718096; text-align: center; margin-top: 20px;">⚡ Generisano pomoću Python Line Counter Premium</p>
    </div>
</body>
</html>"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)
        return output_file


# ==============================================================================
# 👁️ LIVE PREVIEW
# ==============================================================================

WATCHDOG_AVAILABLE = importlib.util.find_spec("watchdog") is not None

if WATCHDOG_AVAILABLE:
    try:
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler
        WATCHDOG_OK = True
    except ImportError:
        WATCHDOG_OK = False
else:
    WATCHDOG_OK = False

if WATCHDOG_OK:
    class PremiumLivePreviewHandler(FileSystemEventHandler):
        def __init__(self, callback):
            self.callback = callback
            self.last_trigger = 0
            self.debounce = Config.DEFAULT['live_preview_debounce']
        
        def on_modified(self, event):
            if not event.is_directory and event.src_path.endswith('.py'):
                now = time.time()
                if now - self.last_trigger > self.debounce:
                    self.last_trigger = now
                    self.callback()
        
        def on_created(self, event):
            if not event.is_directory and event.src_path.endswith('.py'):
                self.callback()
        
        def on_deleted(self, event):
            if not event.is_directory and event.src_path.endswith('.py'):
                self.callback()
    
    class LivePreview:
        @staticmethod
        def start(directory, callback):
            try:
                handler = PremiumLivePreviewHandler(callback)
                observer = Observer()
                observer.schedule(handler, directory, recursive=True)
                observer.start()
                print(f"\n{Color.BOLD}{Color.BRIGHT_GREEN}👁️  LIVE PREVIEW MODE - AKTIVAN{Color.RESET}")
                print(f"{Color.CYAN}   📁 Pratim: {directory}{Color.RESET}")
                print(f"{Color.YELLOW}   ⚡ Pritisni Ctrl+C za zaustavljanje{Color.RESET}\n")
                return observer
            except Exception as e:
                print(f"{Color.RED}❌ Greška: {e}{Color.RESET}")
                return None
else:
    class LivePreview:
        @staticmethod
        def start(directory, callback):
            print(f"\n{Color.RED}❌ Live preview nije dostupan{Color.RESET}")
            print(f"{Color.YELLOW}   📦 Instaliraj: pip install watchdog{Color.RESET}")
            return None


# ==============================================================================
# 🎯 GLAVNI LINE COUNTER
# ==============================================================================

class PythonLineCounter:
    """Premium Python Line Counter"""
    
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
            dirs[:] = [d for d in dirs if d not in ignore_patterns and not d.startswith('.')]
            
            for file in files:
                if file.endswith('.py'):
                    file_path = Path(root) / file
                    
                    try:
                        modified_time = file_path.stat().st_mtime
                        rel_path = file_path.relative_to(self.directory)
                        
                        cached = None
                        if use_cache and self.config.get('use_cache', True):
                            cached = self.cache.get(rel_path, modified_time)
                        
                        if cached:
                            lines = cached['lines']
                            file_size = cached['size']
                            file_hash = cached.get('hash', '')
                            complexity = None
                        else:
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
                        
                        if self.config.get('show_progress', True):
                            bar = PremiumVisualizer.progress_bar(
                                file_count, file_count + 1, width=30,
                                label=f"{Color.GREEN}✓{Color.RESET} Skenirano:",
                                color=Color.GREEN
                            )
                            sys.stdout.write(f"\r{bar}")
                            sys.stdout.flush()
                        
                    except Exception as e:
                        print(f"\n{Color.RED}✗ Greška: {file_path} - {e}{Color.RESET}")
        
        if use_cache and self.files:
            self.cache.save(self.files, {
                'total_files': len(self.files),
                'total_lines': self.total_lines,
                'total_size': self.total_size
            })
        
        scan_time = time.time() - self.start_time
        print(f"\n{Color.GREEN}✅ Skeniranje završeno! {Color.DIM}({scan_time:.2f}s){Color.RESET}")
        print(f"{Color.CYAN}   📊 Pronađeno: {Color.WHITE}{file_count} Python fajlova{Color.RESET}")
        
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
    
    # ==========================================================================
    # 🏆 TOP 10 REKORDERI - NAJVIŠE LINIJA (SORTIRANO OD NAJVEĆEG DO NAJMANJEG)
    # ==========================================================================
    
    def display_top_10_records(self):
        """Prikazuje 10 fajlova sa najviše linija koda - REKORDERI"""
        if not self.files:
            return
        
        # Sortiraj fajlove po broju linija (opadajuće) i uzmi prvih 10
        top_files = sorted(self.files, key=lambda x: x['lines'], reverse=True)[:10]
        total_all_lines = self.total_lines
        max_lines = top_files[0]['lines'] if top_files else 1
        
        print(f"\n{Color.BOLD}{Color.BRIGHT_YELLOW}    ╔══════════════════════════════════════════════════════════════════════════════════╗{Color.RESET}")
        print(f"{Color.BOLD}{Color.BRIGHT_YELLOW}    ║                           🏆  TOP 10 RANG LISTA - REKORDERI                      ║{Color.RESET}")
        print(f"{Color.BOLD}{Color.BRIGHT_YELLOW}    ╚══════════════════════════════════════════════════════════════════════════════════╝{Color.RESET}")
        print()
        
        # Zaglavlje tabele
        print(f"    ┌────┬──────────────────────────────────────────────────┬────────────┬────────────┬──────────────────┐")
        print(f"    │ {Color.BOLD}#{Color.RESET}   │ {Color.BOLD}FAJL{Color.RESET}                                            │ {Color.BOLD}LINIJA{Color.RESET}     │ {Color.BOLD}VELIČINA{Color.RESET}   │ {Color.BOLD}PROCENAT{Color.RESET}         │")
        print(f"    ├────┼──────────────────────────────────────────────────┼────────────┼────────────┼──────────────────┤")
        
        medals = ["🥇 ", "🥈 ", "🥉 "]
        
        for i, f in enumerate(top_files, 1):
            # Formatiraj putanju
            path = str(f['rel_path'])
            if len(path) > 45:
                path = path[:42] + "..."
            
            lines = f['lines']
            size_kb = f['size'] / 1024
            percentage = (lines / total_all_lines * 100) if total_all_lines > 0 else 0
            
            # Boje za rang
            if i == 1:
                rank = f"{Color.BRIGHT_YELLOW}{medals[0]}{Color.RESET}"
                line_color = Color.BRIGHT_RED
                size_color = Color.BRIGHT_MAGENTA
                bar_color = Color.BRIGHT_GREEN
            elif i == 2:
                rank = f"{Color.BRIGHT_WHITE}{medals[1]}{Color.RESET}"
                line_color = Color.RED
                size_color = Color.MAGENTA
                bar_color = Color.GREEN
            elif i == 3:
                rank = f"{Color.BRIGHT_MAGENTA}{medals[2]}{Color.RESET}"
                line_color = Color.YELLOW
                size_color = Color.BLUE
                bar_color = Color.YELLOW
            else:
                rank = f"{Color.CYAN}{i:2}. {Color.RESET}"
                line_color = Color.CYAN
                size_color = Color.BLUE
                bar_color = Color.CYAN
            
            # Progress bar
            bar_width = 16
            filled = int((lines / max_lines) * bar_width)
            bar = f"{bar_color}{'█' * filled}{Color.RESET}{Color.GRAY}{'░' * (bar_width - filled)}{Color.RESET}"
            
            # Ispis reda
            print(f"    │ {rank} │ {Color.WHITE}{path:<45}{Color.RESET} │ {line_color}{lines:>10,}{Color.RESET} │ {size_color}{size_kb:>10.2f} KB{Color.RESET} │ {bar} {Color.CYAN}{percentage:>5.1f}%{Color.RESET} │")
        
        print(f"    ├────┼──────────────────────────────────────────────────┼────────────┼────────────┼──────────────────┤")
        
        # Statistika za top 10
        top10_lines = sum(f['lines'] for f in top_files)
        top10_percentage = (top10_lines / total_all_lines * 100) if total_all_lines > 0 else 0
        top10_size = sum(f['size'] for f in top_files) / 1024
        top10_size_mb = top10_size / 1024
        
        print(f"    │    │ {Color.BOLD}UKUPNO (TOP 10){Color.RESET}                                   │ {Color.BOLD}{Color.YELLOW}{top10_lines:>10,}{Color.RESET} │ {Color.BOLD}{Color.BLUE}{top10_size:>10.2f} KB{Color.RESET} │ {Color.BOLD}{top10_percentage:>5.1f}%{Color.RESET} od ukupno   │")
        print(f"    └────┴──────────────────────────────────────────────────┴────────────┴────────────┴──────────────────┘")
        
        # Dodatna statistika
        print(f"\n    {Color.BOLD}{Color.CYAN}📊 STATISTIKA REKORDERA:{Color.RESET}")
        print(f"    • 🥇 Prvo mesto:  {Color.WHITE}{top_files[0]['rel_path']}{Color.RESET}")
        print(f"      ➜ {Color.YELLOW}{top_files[0]['lines']:,}{Color.RESET} linija • {Color.BLUE}{top_files[0]['size']/1024:.2f} KB{Color.RESET} • {Color.CYAN}{top_files[0]['lines']/total_all_lines*100:.1f}%{Color.RESET} ukupnog koda")
        
        if len(top_files) > 1:
            print(f"    • 🥈 Drugo mesto: {Color.WHITE}{top_files[1]['rel_path']}{Color.RESET}")
            print(f"      ➜ {Color.YELLOW}{top_files[1]['lines']:,}{Color.RESET} linija • {Color.BLUE}{top_files[1]['size']/1024:.2f} KB{Color.RESET}")
            print(f"    • 🥉 Treće mesto: {Color.WHITE}{top_files[2]['rel_path'] if len(top_files) > 2 else '/'}{Color.RESET}")
            
            # Razlike
            print(f"\n    {Color.BOLD}📈 RAZLIKE:{Color.RESET}")
            print(f"    • 1. - 2.: {Color.YELLOW}{top_files[0]['lines'] - top_files[1]['lines']:+7,}{Color.RESET} linija")
            if len(top_files) > 2:
                print(f"    • 2. - 3.: {Color.YELLOW}{top_files[1]['lines'] - top_files[2]['lines']:+7,}{Color.RESET} linija")
            print(f"    • 1. - 10.: {Color.YELLOW}{top_files[0]['lines'] - top_files[9]['lines']:+7,}{Color.RESET} linija")
        
        print(f"\n    {Color.BOLD}📦 ZBIRNO:{Color.RESET}")
        print(f"    • TOP 10 čini {Color.BOLD}{top10_percentage:.1f}%{Color.RESET} ukupnog koda ({Color.YELLOW}{top10_lines:,}{Color.RESET} od {Color.YELLOW}{total_all_lines:,}{Color.RESET} linija)")
        print(f"    • TOP 10 zauzima {Color.BOLD}{top10_size:.2f} KB{Color.RESET} ({top10_size_mb:.3f} MB)")
        print(f"    • Prosek TOP 10: {Color.GREEN}{top10_lines/10:.0f}{Color.RESET} linija po fajlu")
        
        # Poređenje sa ostalima
        other_files = len(self.files) - 10
        if other_files > 0:
            other_lines = total_all_lines - top10_lines
            other_percentage = (other_lines / total_all_lines * 100) if total_all_lines > 0 else 0
            print(f"    • Ostalih {other_files} fajlova: {Color.GRAY}{other_lines:,}{Color.RESET} linija ({other_percentage:.1f}%)")
    
    def display_results(self):
        """Prikazuje glavne rezultate"""
        if not self.files:
            print(f"\n{Color.RED}❌ Nema Python fajlova za prikaz!{Color.RESET}")
            return
        
        table_data = []
        for f in self.files[:100]:
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
        """Prikazuje statistiku"""
        if not self.files:
            return
        
        total_files = len(self.files)
        avg_lines = self.total_lines / total_files if total_files > 0 else 0
        avg_size = self.total_size / total_files if total_files > 0 else 0
        avg_kb, _ = PerfectTable.format_size(avg_size)
        total_kb, total_mb = PerfectTable.format_size(self.total_size)
        
        largest_lines = max(self.files, key=lambda x: x['lines'])
        largest_size = max(self.files, key=lambda x: x['size'])
        
        print(f"\n{Color.BOLD}{Color.BRIGHT_CYAN}📊 STATISTIKA{Color.RESET}")
        print("┌─────────────────────────────────────────────────────────────────┐")
        print(f"│ {Color.BOLD}📈 OSNOVNI PODACI{Color.RESET}")
        print(f"│   • Ukupno fajlova:     {Color.YELLOW}{total_files:>8,}{Color.RESET}")
        print(f"│   • Ukupno linija:      {Color.YELLOW}{self.total_lines:>8,}{Color.RESET}")
        print(f"│   • Ukupna veličina:    {Color.YELLOW}{total_kb:>8} KB{Color.RESET} ({total_mb} MB)")
        print(f"│   • Prosečno linija:    {Color.YELLOW}{avg_lines:>8.1f}{Color.RESET}")
        print(f"│   • Prosečna veličina:  {Color.YELLOW}{avg_kb:>8} KB{Color.RESET}")
        print("├─────────────────────────────────────────────────────────────────┤")
        print(f"│ {Color.BOLD}🏆 REKORDERI{Color.RESET}")
        print(f"│   • Najviše linija:     {Color.YELLOW}{largest_lines['lines']:>8,}{Color.RESET}  {Color.WHITE}{largest_lines['name'][:30]}{Color.RESET}")
        print(f"│   • Najveći fajl:       {Color.BLUE}{largest_size['size']/1024:>8.2f} KB{Color.RESET}  {Color.WHITE}{largest_size['name'][:30]}{Color.RESET}")
        
        if self.start_time:
            scan_time = time.time() - self.start_time
            cache_stats = self.cache.get_stats()
            print("├─────────────────────────────────────────────────────────────────┤")
            print(f"│ {Color.BOLD}⚡ PERFORMANSE{Color.RESET}")
            print(f"│   • Vreme skeniranja:  {Color.CYAN}{scan_time:>8.2f} s{Color.RESET}")
            print(f"│   • Keširano fajlova:  {Color.CYAN}{cache_stats['files']:>8}{Color.RESET}")
        
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
        
        sorted_dirs = sorted(dir_stats.items(), key=lambda x: x[1]['lines'], reverse=True)[:20]
        
        table_data = []
        for dir_path, stats in sorted_dirs:
            path_display = dir_path[:27] + "..." if len(dir_path) > 30 else dir_path
            kb, mb = PerfectTable.format_size(stats['size'])
            table_data.append([path_display, str(stats['files']), str(stats['lines']), kb, mb])
        
        total_kb, total_mb = PerfectTable.format_size(self.total_size)
        totals = ["UKUPNO", str(len(self.files)), str(self.total_lines), total_kb, total_mb]
        
        table = self.table_maker.create(
            headers=["DIREKTORIJUM", "FAJLOVI", "LINIJA", "KB", "MB"],
            data=table_data,
            totals=totals,
            title=f"{Color.CYAN}📂 DIREKTORIJUMI{Color.RESET}",
            max_col_widths=[35, 8, 10, 10, 10]
        )
        
        print(f"\n{table}")
    
    def display_complexity_analysis(self):
        """Prikazuje analizu kompleksnosti"""
        if not self.files:
            return
        
        complex_files = [f for f in self.files if 'complexity' in f and f['complexity']]
        if not complex_files:
            print(f"\n{Color.YELLOW}⚠️  Nema podataka o kompleksnosti{Color.RESET}")
            return
        
        total_score = sum(f['complexity'].get('complexity_score', 0) for f in complex_files)
        avg_score = total_score / len(complex_files) if complex_files else 0
        
        print(f"\n{Color.BOLD}{Color.BRIGHT_MAGENTA}🧠 ANALIZA KOMPLEKSNOSTI{Color.RESET}")
        print("┌─────────────────────────────────────────────────────────────────┐")
        print(f"│   • Ukupni skor:        {Color.MAGENTA}{total_score:>8.2f}{Color.RESET}")
        print(f"│   • Prosečni skor:      {Color.MAGENTA}{avg_score:>8.2f}{Color.RESET}")
        print(f"│   • Analizirano:        {Color.CYAN}{len(complex_files):>8}{Color.RESET} fajlova")
        
        levels = {'NISKA': 0, 'SREDNJA': 0, 'VISOKA': 0, 'KRITIČNA': 0}
        for f in complex_files:
            level = PerfectTable.strip_colors(f['complexity'].get('complexity_level', ''))
            if level in levels:
                levels[level] += 1
        
        print("├─────────────────────────────────────────────────────────────────┤")
        print(f"│ {Color.BOLD}📈 NIVOI KOMPLEKSNOSTI{Color.RESET}")
        
        for level, count in levels.items():
            if count > 0:
                percentage = count / len(complex_files) * 100
                color = (Color.GREEN if level == 'NISKA' else 
                        Color.YELLOW if level == 'SREDNJA' else 
                        Color.MAGENTA if level == 'VISOKA' else Color.RED)
                bar = PremiumVisualizer.progress_bar(
                    count, len(complex_files), width=30,
                    label=f"   • {level:9}", color=color
                )
                print(f"│ {bar}")
        
        print("└─────────────────────────────────────────────────────────────────┘")
    
    def display_duplicates(self):
        """Prikazuje duple fajlove"""
        duplicates = DuplicateFileDetector.find_exact_duplicates(self.files)
        
        if not duplicates:
            print(f"\n{Color.GREEN}✅ Nema duplih fajlova!{Color.RESET}")
            return
        
        print(f"\n{Color.BOLD}{Color.BRIGHT_YELLOW}🔄 DUPLI FAJLOVI ({len(duplicates)}){Color.RESET}")
        print("┌─────────────────────────────────────────────────────────────────┐")
        
        for i, dup in enumerate(duplicates[:10], 1):
            print(f"│ {Color.BOLD}Grupa {i}:{Color.RESET} {Color.CYAN}{dup['hash']}{Color.RESET} ({dup['count']} kopije, {dup['size']:.1f} KB)")
            for j, path in enumerate(dup['files'][:3], 1):
                print(f"│   {j}. {path}")
            if len(dup['files']) > 3:
                print(f"│   ... i još {len(dup['files']) - 3} fajlova")
            if i < len(duplicates[:10]):
                print("├─────────────────────────────────────────────────────────────────┤")
        
        print("└─────────────────────────────────────────────────────────────────┘")


# ==============================================================================
# 🚀 MAIN
# ==============================================================================

def main():
    """Glavna funkcija"""
    
    if sys.platform == "win32":
        os.system("color")
    
    parser = argparse.ArgumentParser(
        description=f'''
{Color.BOLD}{Color.BRIGHT_CYAN}╔════════════════════════════════════════════════════════════════╗
║              🐍 PYTHON LINE COUNTER PREMIUM 2.0              ║
║         Savršeno poravnate tabele | Analiza | Export         ║
╚════════════════════════════════════════════════════════════════╝{Color.RESET}
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('directory', nargs='?', default='.', help='Direktorijum')
    parser.add_argument('-a', '--all', action='store_true', help='Sve opcije')
    parser.add_argument('-c', '--complexity', action='store_true', help='Analiza kompleksnosti')
    parser.add_argument('-d', '--dirs', action='store_true', help='Prikaži direktorijume')
    parser.add_argument('--top10', action='store_true', help='Prikaži TOP 10 rekordere')
    parser.add_argument('--duplicates', action='store_true', help='Pronađi duple fajlove')
    parser.add_argument('--git', action='store_true', help='Git statistika')
    parser.add_argument('--live', action='store_true', help='Live preview')
    parser.add_argument('--export', choices=['json', 'csv', 'html'], help='Export format')
    parser.add_argument('--output', help='Izlazni fajl')
    parser.add_argument('--sort', choices=['path', 'lines', 'size', 'complexity'], default='path')
    parser.add_argument('--reverse', action='store_true')
    parser.add_argument('--nocache', action='store_true')
    parser.add_argument('--reset-cache', action='store_true')
    parser.add_argument('--cache-stats', action='store_true')
    
    args = parser.parse_args()
    
    config = Config()
    
    if args.cache_stats:
        cache = PremiumCache()
        stats = cache.get_stats()
        print(f"\n{Color.BOLD}{Color.BRIGHT_CYAN}💾 KEŠ STATISTIKA{Color.RESET}")
        print("┌─────────────────────────────────────────────────────────────────┐")
        print(f"│   • Keširani fajlovi:  {Color.YELLOW}{stats['files']:>8}{Color.RESET}")
        print(f"│   • Hash indeks:       {Color.YELLOW}{stats['hashes']:>8}{Color.RESET}")
        print(f"│   • Starost keša:      {Color.CYAN}{stats['age'] / 60:>8.1f} min{Color.RESET}")
        print("└─────────────────────────────────────────────────────────────────┘")
        return
    
    if args.reset_cache:
        PremiumCache().invalidate()
        return
    
    if args.sort:
        config.set('sort_by', args.sort)
    if args.reverse:
        config.set('sort_reverse', True)
    
    if not os.path.isdir(args.directory):
        print(f"{Color.RED}❌ Direktorijum '{args.directory}' ne postoji!{Color.RESET}")
        return
    
    counter = PythonLineCounter(args.directory, config)
    
    if args.live:
        if not WATCHDOG_OK:
            print(f"\n{Color.RED}❌ Live preview nije dostupan!{Color.RESET}")
            print(f"{Color.YELLOW}   📦 Instaliraj: pip install watchdog{Color.RESET}")
            return
        
        def refresh():
            counter.scan(not args.nocache, args.complexity or args.all)
            counter.display_results()
            if args.top10 or args.all:
                counter.display_top_10_records()
        
        observer = LivePreview.start(args.directory, refresh)
        if observer:
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print(f"\n{Color.YELLOW}⏹️  Live preview zaustavljen{Color.RESET}")
                observer.stop()
                observer.join()
        return
    
    try:
        analyze = args.complexity or args.all or args.top10 or args.duplicates
        counter.scan(not args.nocache, analyze)
        
        if not counter.files:
            print(f"\n{Color.YELLOW}ℹ️  Nema Python fajlova{Color.RESET}")
            return
        
        print(f"\n{Color.GREEN}{'═' * 70}{Color.RESET}")
        counter.display_results()
        
        if args.dirs or args.all:
            counter.display_directory_summary()
        
        # 🏆 PRIKAŽI TOP 10 REKORDERE - SORTIRANO OD NAJVEĆEG DO NAJMANJEG
        if args.top10 or args.all:
            counter.display_top_10_records()
        
        if args.complexity or args.all:
            counter.display_complexity_analysis()
        
        if args.duplicates or args.all:
            counter.display_duplicates()
        
        if args.git or args.all:
            git_stats = GitStatsCollector.collect(args.directory)
            if git_stats:
                print(f"\n{Color.BOLD}{Color.BRIGHT_CYAN}🔧 GIT STATISTIKA{Color.RESET}")
                print("┌─────────────────────────────────────────────────────────────────┐")
                print(f"│   • Commitova:  {Color.YELLOW}{git_stats['total_commits']:>8,}{Color.RESET}")
                print(f"│   • Autora:     {Color.YELLOW}{len(git_stats['authors']):>8}{Color.RESET}")
                print(f"│   • Grane:      {Color.YELLOW}{git_stats['branches']:>8}{Color.RESET}")
                print(f"│   • Tagovi:     {Color.YELLOW}{git_stats['tags']:>8}{Color.RESET}")
                if 'last_commit' in git_stats:
                    lc = git_stats['last_commit']
                    print("├─────────────────────────────────────────────────────────────────┤")
                    print(f"│   • Poslednji:  {Color.CYAN}{lc['hash']}{Color.RESET}")
                    print(f"│     {lc['author']}: {lc['message'][:40]}")
                print("└─────────────────────────────────────────────────────────────────┘")
        
        if args.export:
            exporter = PremiumExporter()
            output = args.output
            try:
                if args.export == 'json':
                    output = exporter.to_json(counter.files, output)
                elif args.export == 'csv':
                    output = exporter.to_csv(counter.files, output)
                elif args.export == 'html':
                    output = exporter.to_html(counter.files, output)
                print(f"\n{Color.GREEN}✅ Export: {output}{Color.RESET}")
            except Exception as e:
                print(f"\n{Color.RED}❌ Greška pri exportu: {e}{Color.RESET}")
        
        print(f"\n{Color.BOLD}{Color.BRIGHT_GREEN}✅ ANALIZA ZAVRŠENA{Color.RESET}")
        
    except KeyboardInterrupt:
        print(f"\n\n{Color.YELLOW}⏹️  Prekinuto{Color.RESET}")
    except Exception as e:
        print(f"\n{Color.RED}❌ Greška: {e}{Color.RESET}")
        if os.environ.get('DEBUG'):
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    main()