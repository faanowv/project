#!/usr/bin/env python3
"""
🔐 Анализатор безопасности сайтов
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import requests
import whois
import socket
import ssl
import re
from urllib.parse import urlparse
from datetime import datetime
import time
from collections import Counter
import dns.resolver
import tldextract
import warnings
from bs4 import BeautifulSoup

warnings.filterwarnings('ignore')


class WebsiteSecurityAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Анализатор Безопасности Сайтов")
        self.root.geometry("1100x850")
        self.root.configure(bg='#f5f7fa')

        # Настройки
        self.timeout = 5

        # Белый список легитимных сайтов
        self.whitelist = {
            'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'wikipedia.org',
            'twitter.com', 'github.com', 'stackoverflow.com', 'reddit.com', 'netflix.com'
        }

        # Подозрительные паттерны
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz']

        self.setup_styles()
        self.setup_ui()
        self.setup_context_menu()

        self.analysis_results = {}
        self.safety_score = 0
        self.is_analyzing = False
        self.site_content_analysis = {}

    def setup_styles(self):
        self.colors = {
            'primary': '#3498db',
            'success': '#2ecc71',
            'warning': '#f39c12',
            'danger': '#e74c3c',
            'dark': '#2c3e50',
            'light': '#ecf0f1',
            'gray': '#95a5a6',
            'excellent': '#27ae60',
            'good': '#2ecc71',
            'medium': '#f1c40f',
            'poor': '#e67e22',
            'critical': '#e74c3c'
        }

    def setup_ui(self):
        # Основной контейнер
        main_container = tk.Frame(self.root, bg=self.colors['light'])
        main_container.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

        # Верхняя панель
        self.setup_header(main_container)

        # Центральная область
        self.setup_main_area(main_container)

        # Нижняя панель
        self.setup_footer(main_container)

    def setup_header(self, parent):
        header_frame = tk.Frame(parent, bg=self.colors['dark'], height=70)
        header_frame.pack(fill=tk.X, pady=(0, 15))
        header_frame.pack_propagate(False)

        title_label = tk.Label(
            header_frame,
            text="🔐 АНАЛИЗАТОР БЕЗОПАСНОСТИ САЙТОВ",
            font=("Arial", 18, "bold"),
            bg=self.colors['dark'],
            fg='white'
        )
        title_label.pack(expand=True)

    def setup_main_area(self, parent):
        # Панель ввода
        input_frame = tk.Frame(parent, bg=self.colors['light'])
        input_frame.pack(fill=tk.X, pady=(0, 15))

        input_label = tk.Label(
            input_frame,
            text="🌐 Введите URL для анализа безопасности:",
            font=("Arial", 12, "bold"),
            bg=self.colors['light'],
            fg=self.colors['dark']
        )
        input_label.pack(anchor=tk.W, padx=20, pady=(0, 10))

        input_container = tk.Frame(input_frame, bg=self.colors['light'])
        input_container.pack(fill=tk.X, padx=20)

        self.url_entry = tk.Entry(
            input_container,
            width=70,
            font=("Arial", 11),
            relief=tk.SOLID,
            bd=2
        )
        self.url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        self.url_entry.insert(0, "https://google.com")

        # Кнопка "Вставить"
        self.paste_button = tk.Button(
            input_container,
            text="📋 Вставить",
            command=self.paste_from_clipboard,
            bg=self.colors['light'],
            fg=self.colors['primary'],
            font=("Arial", 10),
            relief=tk.FLAT,
            cursor="hand2",
            padx=15,
            pady=5
        )
        self.paste_button.pack(side=tk.LEFT, padx=(0, 10))

        self.analyze_button = tk.Button(
            input_container,
            text="🚀 АНАЛИЗИРОВАТЬ",
            command=self.start_analysis,
            bg=self.colors['primary'],
            fg='white',
            font=("Arial", 11, "bold"),
            relief=tk.FLAT,
            padx=30,
            pady=12,
            cursor="hand2"
        )
        self.analyze_button.pack(side=tk.LEFT)

        # Быстрые ссылки
        self.setup_quick_links(input_frame)

        # Прогресс и статус
        self.setup_progress_area(parent)

        # Вкладки результатов
        self.setup_tabs(parent)

    def setup_quick_links(self, parent):
        quick_frame = tk.Frame(parent, bg=self.colors['light'])
        quick_frame.pack(fill=tk.X, padx=20, pady=(10, 0))

        quick_label = tk.Label(
            quick_frame,
            text="Быстрая проверка:",
            font=("Arial", 9),
            bg=self.colors['light'],
            fg=self.colors['gray']
        )
        quick_label.pack(side=tk.LEFT)

        test_sites = [
            ("Google", "https://google.com"),
            ("GitHub", "https://github.com"),
            ("Wikipedia", "https://wikipedia.org"),
            ("Test Site", "http://httpbin.org")
        ]

        for name, url in test_sites:
            btn = tk.Button(
                quick_frame,
                text=name,
                command=lambda u=url: self.url_entry.delete(0, tk.END) or self.url_entry.insert(0, u),
                font=("Arial", 9),
                bg=self.colors['light'],
                fg=self.colors['primary'],
                relief=tk.FLAT,
                cursor="hand2",
                padx=8,
                pady=2
            )
            btn.pack(side=tk.LEFT, padx=5)

    def setup_progress_area(self, parent):
        self.progress_frame = tk.Frame(parent, bg=self.colors['light'])
        self.progress_frame.pack(fill=tk.X, pady=(0, 15))

        self.status_label = tk.Label(
            self.progress_frame,
            text="Готов к анализу",
            font=("Arial", 10),
            bg=self.colors['light'],
            fg=self.colors['dark']
        )
        self.status_label.pack()

        self.progress = ttk.Progressbar(
            self.progress_frame,
            mode='indeterminate',
            length=400
        )
        self.progress.pack(fill=tk.X, padx=50, pady=(5, 0))

    def setup_tabs(self, parent):
        style = ttk.Style()
        style.configure("Custom.TNotebook", background=self.colors['light'])

        self.notebook = ttk.Notebook(parent)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self.create_tabs()

    def create_tabs(self):
        self.summary_tab = self.create_tab_frame("📊 Сводка")
        self.security_tab = self.create_tab_frame("🔐 Безопасность")
        self.authenticity_tab = self.create_tab_frame("🛡️ Аутентичность")
        self.performance_tab = self.create_tab_frame("⚡ Производительность")
        self.siteinfo_tab = self.create_tab_frame("ℹ️ Информация")
        self.recommendations_tab = self.create_tab_frame("💡 Рекомендации")

        self.setup_summary_tab()
        self.setup_security_tab()
        self.setup_authenticity_tab()
        self.setup_performance_tab()
        self.setup_siteinfo_tab()
        self.setup_recommendations_tab()

    def create_tab_frame(self, text):
        frame = tk.Frame(self.notebook, bg='white')
        self.notebook.add(frame, text=text)
        return frame

    def setup_summary_tab(self):
        container = tk.Frame(self.summary_tab, bg='white')
        container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        top_frame = tk.Frame(container, bg='white')
        top_frame.pack(fill=tk.X, pady=(0, 20))

        self.score_canvas = tk.Canvas(top_frame, width=150, height=150, bg='white', highlightthickness=0)
        self.score_canvas.pack(side=tk.LEFT, padx=(0, 30))

        score_info = tk.Frame(top_frame, bg='white')
        score_info.pack(side=tk.LEFT, fill=tk.Y)

        self.score_value = tk.Label(
            score_info,
            text="--",
            font=("Arial", 40, "bold"),
            bg='white',
            fg=self.colors['gray']
        )
        self.score_value.pack(anchor=tk.W)

        self.score_label = tk.Label(
            score_info,
            text="из 100 баллов",
            font=("Arial", 12),
            bg='white',
            fg=self.colors['gray']
        )
        self.score_label.pack(anchor=tk.W, pady=(0, 15))

        self.risk_label = tk.Label(
            score_info,
            text="Уровень риска: --",
            font=("Arial", 14, "bold"),
            bg='white',
            fg=self.colors['gray']
        )
        self.risk_label.pack(anchor=tk.W)

        metrics_frame = tk.Frame(container, bg='white')
        metrics_frame.pack(fill=tk.X, pady=(0, 20))

        metrics = [
            ("🔐 Безопасность", "security_score", '#2ecc71'),
            ("🛡️ Аутентичность", "authenticity_score", '#3498db'),
            ("⚡ Производительность", "performance_score", '#f39c12'),
            ("📊 Качество", "quality_score", '#9b59b6')
        ]

        for name, key, color in metrics:
            frame = tk.Frame(metrics_frame, bg='white')
            frame.pack(side=tk.LEFT, expand=True, fill=tk.BOTH, padx=3)

            tk.Label(frame, text=name, font=("Arial", 10, "bold"), bg='white').pack()

            value_label = tk.Label(frame, text="--/25", font=("Arial", 16, "bold"), bg='white', fg=color)
            value_label.pack(pady=2)

            progress = ttk.Progressbar(frame, orient='horizontal', length=80, mode='determinate')
            progress.pack(pady=2)
            progress['value'] = 0

            setattr(self, f"{key}_label", value_label)
            setattr(self, f"{key}_progress", progress)

        info_frame = tk.LabelFrame(container, text="📋 Краткая информация",
                                   font=("Arial", 11, "bold"), bg='white', relief=tk.GROOVE, bd=1)
        info_frame.pack(fill=tk.BOTH, expand=True)

        self.summary_text = scrolledtext.ScrolledText(
            info_frame,
            wrap=tk.WORD,
            font=("Consolas", 9),
            bg='#f8f9fa',
            height=10
        )
        self.summary_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def setup_security_tab(self):
        container = tk.Frame(self.security_tab, bg='white')
        container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        columns = ('check', 'status', 'score', 'details')
        self.security_tree = ttk.Treeview(container, columns=columns, show='headings', height=20)

        for col, heading, width in [('check', 'Критерий проверки', 250),
                                    ('status', 'Статус', 100),
                                    ('score', 'Баллы', 80),
                                    ('details', 'Детали', 320)]:
            self.security_tree.heading(col, text=heading)
            self.security_tree.column(col, width=width)

        scrollbar = ttk.Scrollbar(container, orient=tk.VERTICAL, command=self.security_tree.yview)
        self.security_tree.configure(yscrollcommand=scrollbar.set)
        self.security_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def setup_authenticity_tab(self):
        container = tk.Frame(self.authenticity_tab, bg='white')
        container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        main_frame = tk.Frame(container, bg='white')
        main_frame.pack(fill=tk.BOTH, expand=True)

        self.authenticity_indicator = tk.Label(
            main_frame,
            text="🔍 АУТЕНТИЧНОСТЬ: --",
            font=("Arial", 16, "bold"),
            bg='white',
            fg=self.colors['gray']
        )
        self.authenticity_indicator.pack(pady=(0, 15))

        clone_frame = tk.LabelFrame(main_frame, text="🕵️ Проверка на клон/фишинг",
                                    font=("Arial", 11, "bold"), bg='white', relief=tk.GROOVE, bd=1)
        clone_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))

        self.clone_text = scrolledtext.ScrolledText(
            clone_frame,
            wrap=tk.WORD,
            font=("Consolas", 9),
            bg='#f8f9fa',
            height=8
        )
        self.clone_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        domain_frame = tk.LabelFrame(main_frame, text="🌐 Информация о домене",
                                     font=("Arial", 11, "bold"), bg='white', relief=tk.GROOVE, bd=1)
        domain_frame.pack(fill=tk.BOTH, expand=True)

        self.domain_text = scrolledtext.ScrolledText(
            domain_frame,
            wrap=tk.WORD,
            font=("Consolas", 9),
            bg='#f8f9fa',
            height=6
        )
        self.domain_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def setup_performance_tab(self):
        container = tk.Frame(self.performance_tab, bg='white')
        container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        self.performance_text = scrolledtext.ScrolledText(
            container,
            wrap=tk.WORD,
            font=("Consolas", 10),
            bg='#f8f9fa',
            height=22
        )
        self.performance_text.pack(fill=tk.BOTH, expand=True)

    def setup_siteinfo_tab(self):
        container = tk.Frame(self.siteinfo_tab, bg='white')
        container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        info_frame = tk.LabelFrame(container, text="ℹ️ Основная информация",
                                   font=("Arial", 12, "bold"), bg='white', relief=tk.GROOVE, bd=1)
        info_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))

        self.site_info_text = scrolledtext.ScrolledText(
            info_frame,
            wrap=tk.WORD,
            font=("Consolas", 10),
            bg='#f8f9fa',
            height=10
        )
        self.site_info_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        content_frame = tk.LabelFrame(container, text="📊 Анализ контента",
                                      font=("Arial", 12, "bold"), bg='white', relief=tk.GROOVE, bd=1)
        content_frame.pack(fill=tk.BOTH, expand=True)

        self.content_analysis_text = scrolledtext.ScrolledText(
            content_frame,
            wrap=tk.WORD,
            font=("Consolas", 10),
            bg='#f8f9fa',
            height=12
        )
        self.content_analysis_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def setup_recommendations_tab(self):
        container = tk.Frame(self.recommendations_tab, bg='white')
        container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        self.recommendations_text = scrolledtext.ScrolledText(
            container,
            wrap=tk.WORD,
            font=("Consolas", 10),
            bg='#f8f9fa',
            height=28
        )
        self.recommendations_text.pack(fill=tk.BOTH, expand=True)

    def setup_footer(self, parent):
        footer_frame = tk.Frame(parent, bg=self.colors['dark'], height=40)
        footer_frame.pack(fill=tk.X, pady=(15, 0))
        footer_frame.pack_propagate(False)

        tk.Label(footer_frame,
                 text="© 2024 Анализатор Безопасности Сайтов | Для образовательных целей",
                 font=("Arial", 9),
                 bg=self.colors['dark'],
                 fg='#95a5a6').pack(expand=True)

    def setup_context_menu(self):
        """Настройка контекстного меню для поля ввода"""
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Вставить", command=self.paste_from_clipboard)
        self.context_menu.add_command(label="Копировать", command=self.copy_to_clipboard)
        self.context_menu.add_command(label="Вырезать", command=self.cut_to_clipboard)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Выделить все", command=self.select_all_text)

        # Привязываем контекстное меню к полю ввода
        self.url_entry.bind("<Button-3>", self.show_context_menu)

    def show_context_menu(self, event):
        """Показать контекстное меню"""
        self.context_menu.tk_popup(event.x_root, event.y_root)

    def copy_to_clipboard(self):
        """Копировать текст в буфер обмена"""
        try:
            text = self.url_entry.selection_get()
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
        except:
            # Если ничего не выделено, копируем весь текст
            text = self.url_entry.get()
            self.root.clipboard_clear()
            self.root.clipboard_append(text)

    def cut_to_clipboard(self):
        """Вырезать текст в буфер обмена"""
        try:
            text = self.url_entry.selection_get()
            self.root.clipboard_clear()
            self.root.clipboard_append(text)

            # Удаляем выделенный текст
            start = self.url_entry.index(tk.SEL_FIRST)
            end = self.url_entry.index(tk.SEL_LAST)
            self.url_entry.delete(start, end)
        except:
            pass

    def select_all_text(self):
        """Выделить весь текст"""
        self.url_entry.select_range(0, tk.END)
        self.url_entry.icursor(tk.END)

    def paste_from_clipboard(self):
        """Вставка текста из буфера обмена"""
        try:
            # Получаем текст из буфера обмена
            clipboard_text = self.root.clipboard_get()

            if clipboard_text:
                # Очищаем поле и вставляем текст
                self.url_entry.delete(0, tk.END)
                self.url_entry.insert(0, clipboard_text.strip())

                # Прокручиваем в конец
                self.url_entry.xview_moveto(1)

                # Выделяем весь текст для удобства
                self.url_entry.select_range(0, tk.END)
                self.url_entry.icursor(tk.END)

                # Возвращаем фокус на поле ввода
                self.url_entry.focus_set()
        except:
            pass

    def start_analysis(self):
        if self.is_analyzing:
            return

        url = self.url_entry.get().strip()
        if not url or url == "https://":
            messagebox.showwarning("Внимание", "Введите URL сайта")
            return

        self.clear_results()
        self.is_analyzing = True
        self.analyze_button.config(state=tk.DISABLED, text="⏳ Анализ...")
        self.status_label.config(text="Начинаем анализ...")
        self.progress.start()

        thread = threading.Thread(target=self.perform_analysis, args=(url,))
        thread.daemon = True
        thread.start()

    def clear_results(self):
        for item in self.security_tree.get_children():
            self.security_tree.delete(item)

        for text_widget in [self.summary_text, self.clone_text, self.domain_text,
                            self.performance_text, self.site_info_text,
                            self.content_analysis_text, self.recommendations_text]:
            text_widget.delete(1.0, tk.END)

        self.score_value.config(text="--", fg=self.colors['gray'])
        self.score_label.config(text="из 100 баллов")
        self.risk_label.config(text="Уровень риска: --", fg=self.colors['gray'])
        self.authenticity_indicator.config(text="🔍 АУТЕНТИЧНОСТЬ: --", fg=self.colors['gray'])

        for key in ['security_score', 'authenticity_score', 'performance_score', 'quality_score']:
            progress = getattr(self, f"{key}_progress")
            progress['value'] = 0
            label = getattr(self, f"{key}_label")
            label.config(text="--/25")

    def perform_analysis(self, url):
        """Основной метод анализа"""
        try:
            # Нормализуем URL
            parsed_url = self.normalize_url(url)
            if not parsed_url:
                self.show_error("Некорректный URL")
                return

            domain = urlparse(parsed_url).netloc

            # Выполняем проверки
            checks = []

            # 1. Базовая доступность
            self.update_status("Проверка доступности...")
            availability = self.check_availability(parsed_url)
            checks.append({'category': 'security', 'name': 'Доступность сайта', **availability})

            # 2. Проверка HTTPS
            self.update_status("Проверка HTTPS...")
            https_check = self.check_https(parsed_url)
            checks.append({'category': 'security', 'name': 'HTTPS протокол', **https_check})

            # 3. Проверка SSL сертификата
            if https_check['score'] > 0:
                self.update_status("Проверка SSL...")
                ssl_check = self.check_ssl_certificate(parsed_url)
                checks.append({'category': 'security', 'name': 'SSL сертификат', **ssl_check})

            # 4. Проверка заголовков безопасности
            if availability['score'] > 0:
                self.update_status("Проверка заголовков...")
                headers_check = self.check_security_headers(parsed_url)
                checks.append({'category': 'security', 'name': 'Заголовки безопасности', **headers_check})

            # 5. Проверка домена
            self.update_status("Анализ домена...")
            domain_check = self.check_domain_security(domain)
            checks.append({'category': 'authenticity', 'name': 'Безопасность домена', **domain_check})

            # 6. Проверка производительности
            if availability['score'] > 0:
                self.update_status("Проверка скорости...")
                performance_check = self.check_performance(parsed_url)
                checks.append({'category': 'performance', 'name': 'Производительность', **performance_check})

                # Анализ контента
                self.update_status("Анализ контента...")
                content_info = self.analyze_content(parsed_url)
                self.site_content_analysis = content_info

                # Проверка контента на безопасность
                content_check = self.check_content_security(parsed_url)
                checks.append({'category': 'security', 'name': 'Безопасность контента', **content_check})

            # 7. Проверка DNS
            self.update_status("Проверка DNS...")
            dns_check = self.check_dns_records(domain)
            checks.append({'category': 'security', 'name': 'DNS записи', **dns_check})

            # 8. Проверка на фишинг
            self.update_status("Проверка на фишинг...")
            phishing_check = self.check_for_phishing(domain)
            checks.append({'category': 'authenticity', 'name': 'Проверка на фишинг', **phishing_check})

            # 9. Проверка структуры сайта
            if availability['score'] > 0:
                self.update_status("Анализ структуры...")
                structure_check = self.check_site_structure(parsed_url)
                checks.append({'category': 'quality', 'name': 'Структура сайта', **structure_check})

            # 10. Проверка HTTP редиректа
            self.update_status("Проверка редиректов...")
            redirect_check = self.check_redirects(parsed_url)
            checks.append({'category': 'security', 'name': 'HTTP редиректы', **redirect_check})

            # Расчет итоговой оценки
            if checks:
                total_score = sum(c.get('score', 0) for c in checks)
                total_max = sum(c.get('max_score', 0) for c in checks)
                self.safety_score = int((total_score / total_max) * 100) if total_max > 0 else 0

                self.analysis_results = {
                    'url': url,
                    'checks': checks,
                    'total_score': self.safety_score,
                    'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }

                # Обновление UI
                self.root.after(0, self.update_results_ui)
                self.root.after(0, self.update_site_info_tab)
                self.root.after(0, self.update_authenticity_info, domain, checks)
                self.root.after(0, self.generate_reports)
            else:
                self.show_error("Не удалось выполнить проверки")

        except Exception as e:
            self.show_error(f"Ошибка при анализе: {str(e)}")
        finally:
            self.root.after(0, self.analysis_complete)

    def normalize_url(self, url):
        """Нормализация URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        try:
            parsed = urlparse(url)
            if not parsed.netloc:
                return None

            # Убираем www
            domain = parsed.netloc.lower()
            if domain.startswith('www.'):
                domain = domain[4:]

            return f"{parsed.scheme}://{domain}"
        except:
            return None

    def check_availability(self, url):
        """Проверка доступности сайта"""
        try:
            headers = {'User-Agent': 'Mozilla/5.0'}
            start_time = time.time()
            response = requests.get(url, headers=headers, timeout=self.timeout, allow_redirects=True)
            response_time = time.time() - start_time

            if response.status_code == 200:
                if response_time < 2:
                    return {'score': 10, 'max_score': 10, 'status': '✅ Отлично',
                            'details': f'Доступен за {response_time:.2f} секунд'}
                else:
                    return {'score': 7, 'max_score': 10, 'status': '⚠️ Нормально',
                            'details': f'Доступен за {response_time:.2f} секунд'}
            else:
                return {'score': 4, 'max_score': 10, 'status': '⚠️ Проблемы',
                        'details': f'Код ответа: {response.status_code}'}

        except requests.exceptions.Timeout:
            return {'score': 0, 'max_score': 10, 'status': '❌ Таймаут',
                    'details': 'Превышено время ожидания'}
        except Exception as e:
            return {'score': 2, 'max_score': 10, 'status': '⚠️ Ошибка',
                    'details': f'Ошибка подключения'}

    def check_https(self, url):
        """Проверка использования HTTPS"""
        try:
            parsed = urlparse(url)
            if parsed.scheme == 'https':
                return {'score': 10, 'max_score': 10, 'status': '✅ Используется',
                        'details': 'Сайт использует защищенный HTTPS протокол'}
            else:
                return {'score': 0, 'max_score': 10, 'status': '❌ HTTP',
                        'details': 'Используется незащищенный HTTP протокол'}
        except:
            return {'score': 5, 'max_score': 10, 'status': '⚠️ Неизвестно',
                    'details': 'Не удалось проверить протокол'}

    def check_ssl_certificate(self, url):
        """Проверка SSL сертификата"""
        try:
            parsed = urlparse(url)
            hostname = parsed.netloc

            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

                    # Проверяем срок действия
                    if 'notAfter' in cert:
                        not_after = cert['notAfter']
                        # Пытаемся распарсить дату
                        try:
                            if isinstance(not_after, str):
                                cert_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                                days_left = (cert_date - datetime.now()).days

                                if days_left > 30:
                                    return {'score': 10, 'max_score': 10, 'status': '✅ Действителен',
                                            'details': f'SSL действителен еще {days_left} дней'}
                                else:
                                    return {'score': 3, 'max_score': 10, 'status': '⚠️ Скоро истечет',
                                            'details': f'SSL истекает через {days_left} дней'}
                        except:
                            pass

                    return {'score': 8, 'max_score': 10, 'status': '✅ Настроен',
                            'details': 'SSL сертификат настроен'}

        except Exception as e:
            return {'score': 2, 'max_score': 10, 'status': '⚠️ Проблемы',
                    'details': f'SSL не настроен или ошибка проверки'}

    def check_security_headers(self, url):
        """Проверка заголовков безопасности"""
        try:
            headers = {'User-Agent': 'Mozilla/5.0'}
            response = requests.head(url, headers=headers, timeout=5)

            security_headers = [
                'Strict-Transport-Security',
                'X-Frame-Options',
                'X-Content-Type-Options',
                'X-XSS-Protection'
            ]

            found_headers = []
            for header in security_headers:
                if header in response.headers:
                    found_headers.append(header)

            score = len(found_headers) * 2.5  # Максимум 10 баллов

            if score >= 7.5:
                status = '✅ Хорошие'
            elif score >= 5:
                status = '⚠️ Средние'
            else:
                status = '❌ Слабые'

            return {'score': int(score), 'max_score': 10, 'status': status,
                    'details': f'Найдено {len(found_headers)} из {len(security_headers)} заголовков'}

        except Exception:
            return {'score': 0, 'max_score': 10, 'status': '⚠️ Ошибка',
                    'details': 'Не удалось проверить заголовки'}

    def check_domain_security(self, domain):
        """Проверка безопасности домена"""
        extracted = tldextract.extract(domain)
        base_domain = f"{extracted.domain}.{extracted.suffix}"

        score = 15

        # Проверка на белый список
        if base_domain in self.whitelist:
            return {'score': 15, 'max_score': 15, 'status': '✅ Легитимный',
                    'details': 'Домен в списке проверенных сайтов'}

        # Проверка TLD
        if extracted.suffix in self.suspicious_tlds:
            score -= 5

        # Проверка длины
        if len(domain) > 40:
            score -= 3

        # Проверка на фишинг
        phishing_words = ['login', 'secure', 'verify', 'account', 'bank']
        for word in phishing_words:
            if word in domain.lower():
                score -= 2
                break

        if score >= 12:
            status = '✅ Безопасный'
        elif score >= 8:
            status = '⚠️ Подозрительный'
        else:
            status = '❌ Опасный'

        return {'score': max(0, score), 'max_score': 15, 'status': status,
                'details': 'Анализ доменного имени'}

    def check_performance(self, url):
        """Проверка производительности"""
        try:
            headers = {'User-Agent': 'Mozilla/5.0'}
            start_time = time.time()
            response = requests.get(url, headers=headers, timeout=self.timeout)
            load_time = time.time() - start_time

            page_size_kb = len(response.content) / 1024

            # Оценка по времени загрузки
            if load_time < 1.5:
                time_score = 5
                time_status = 'быстро'
            elif load_time < 3:
                time_score = 3
                time_status = 'средне'
            else:
                time_score = 1
                time_status = 'медленно'

            # Оценка по размеру
            if page_size_kb < 500:
                size_score = 5
                size_status = 'оптимальный'
            elif page_size_kb < 2000:
                size_score = 3
                size_status = 'большой'
            else:
                size_score = 1
                size_status = 'очень большой'

            total_score = time_score + size_score

            return {'score': total_score, 'max_score': 10, 'status': '✅ Проверено',
                    'details': f'Загрузка: {load_time:.2f}с ({time_status}), Размер: {page_size_kb:.1f}KB ({size_status})'}

        except Exception:
            return {'score': 0, 'max_score': 10, 'status': '⚠️ Ошибка',
                    'details': 'Не удалось измерить производительность'}

    def analyze_content(self, url):
        """Анализ контента сайта"""
        try:
            headers = {'User-Agent': 'Mozilla/5.0'}
            response = requests.get(url, headers=headers, timeout=self.timeout)
            soup = BeautifulSoup(response.content, 'html.parser')

            title_tag = soup.find('title')
            title = title_tag.get_text(strip=True) if title_tag else 'Не указан'

            meta_desc = soup.find('meta', attrs={'name': 'description'})
            description = meta_desc['content'][:150] + '...' if meta_desc and meta_desc.get('content') else 'Не указано'

            # Определяем тип сайта
            text = soup.get_text().lower()[:1000]
            site_type = 'Информационный'

            if any(word in text for word in ['купить', 'цена', 'рубль', 'корзина']):
                site_type = 'Интернет-магазин'
            elif any(word in text for word in ['новость', 'новости', 'репортаж']):
                site_type = 'Новостной'
            elif any(word in text for word in ['блог', 'пост', 'запись']):
                site_type = 'Блог'

            return {
                'title': title,
                'description': description,
                'site_type': site_type,
                'page_size_kb': len(response.content) / 1024,
                'images_count': len(soup.find_all('img'))
            }

        except Exception:
            return {
                'title': 'Не удалось проанализировать',
                'description': 'Ошибка анализа контента',
                'site_type': 'Неизвестно',
                'page_size_kb': 0,
                'images_count': 0
            }

    def check_content_security(self, url):
        """Проверка безопасности контента"""
        try:
            headers = {'User-Agent': 'Mozilla/5.0'}
            response = requests.get(url, headers=headers, timeout=self.timeout)
            content = response.text.lower()

            score = 10

            # Проверка на скрытые iframe
            if content.count('<iframe') > 5:
                score -= 2

            # Проверка на подозрительные скрипты
            suspicious_patterns = ['eval(', 'document.write', 'fromcharcode']
            for pattern in suspicious_patterns:
                if pattern in content:
                    score -= 1
                    break

            # Проверка на внешние ресурсы
            external_count = content.count('http://') + content.count('https://')
            if external_count > 50:
                score -= 2

            if score >= 8:
                status = '✅ Безопасный'
            elif score >= 6:
                status = '⚠️ Нормальный'
            else:
                status = '❌ Подозрительный'

            return {'score': score, 'max_score': 10, 'status': status,
                    'details': 'Проверка контента на безопасность'}

        except Exception:
            return {'score': 5, 'max_score': 10, 'status': '⚠️ Не проверено',
                    'details': 'Не удалось проверить контент'}

    def check_dns_records(self, domain):
        """Проверка DNS записей"""
        try:
            # Пробуем получить A записи
            answers = dns.resolver.resolve(domain, 'A')
            ip_count = len(answers)

            return {'score': 8, 'max_score': 10, 'status': '✅ Настроены',
                    'details': f'Найдено {ip_count} A записей'}

        except dns.resolver.NXDOMAIN:
            return {'score': 0, 'max_score': 10, 'status': '❌ Не найден',
                    'details': 'Домен не существует'}
        except Exception:
            return {'score': 5, 'max_score': 10, 'status': '⚠️ Ошибка',
                    'details': 'Не удалось проверить DNS'}

    def check_for_phishing(self, domain):
        """Проверка на фишинг"""
        extracted = tldextract.extract(domain)

        score = 10

        # Проверка TLD
        if extracted.suffix in self.suspicious_tlds:
            score -= 3

        # Проверка ключевых слов фишинга
        phishing_keywords = ['login', 'secure', 'verify', 'account', 'bank', 'pay']
        for keyword in phishing_keywords:
            if keyword in domain.lower():
                score -= 2
                break

        # Проверка длины
        if len(domain) > 35:
            score -= 1

        # Проверка на поддомены
        if extracted.subdomain and len(extracted.subdomain.split('.')) > 2:
            score -= 1

        if score >= 8:
            status = '✅ Безопасный'
        elif score >= 6:
            status = '⚠️ Подозрительный'
        else:
            status = '❌ Опасный'

        return {'score': max(0, score), 'max_score': 10, 'status': status,
                'details': 'Анализ на признаки фишинга'}

    def check_site_structure(self, url):
        """Проверка структуры сайта"""
        try:
            headers = {'User-Agent': 'Mozilla/5.0'}
            response = requests.get(url, headers=headers, timeout=self.timeout)
            soup = BeautifulSoup(response.content, 'html.parser')

            score = 10

            # Проверка наличия навигации
            nav_tags = soup.find_all(['nav', 'ul', 'ol'])
            if len(nav_tags) < 1:
                score -= 2

            # Проверка заголовков
            h_tags = soup.find_all(['h1', 'h2', 'h3'])
            if len(h_tags) < 3:
                score -= 1

            # Проверка футера
            footer_tags = soup.find_all(['footer', 'div.footer', 'div#footer'])
            if len(footer_tags) < 1:
                score -= 1

            # Проверка мета-тегов
            meta_tags = soup.find_all('meta')
            important_meta = ['description', 'keywords', 'viewport']
            found_meta = 0
            for meta in meta_tags:
                if meta.get('name') in important_meta:
                    found_meta += 1

            if found_meta < 2:
                score -= 1

            if score >= 8:
                status = '✅ Хорошая'
            elif score >= 6:
                status = '⚠️ Средняя'
            else:
                status = '❌ Плохая'

            return {'score': score, 'max_score': 10, 'status': status,
                    'details': 'Анализ структуры сайта'}

        except Exception:
            return {'score': 5, 'max_score': 10, 'status': '⚠️ Не проверено',
                    'details': 'Не удалось проверить структуру'}

    def check_redirects(self, url):
        """Проверка HTTP редиректов"""
        try:
            # Проверяем редирект с HTTP на HTTPS если сайт на HTTPS
            parsed = urlparse(url)
            if parsed.scheme == 'https':
                http_url = f"http://{parsed.netloc}"
                response = requests.get(http_url, timeout=5, allow_redirects=True)

                if response.url.startswith('https://'):
                    return {'score': 10, 'max_score': 10, 'status': '✅ Настроен',
                            'details': 'Автоматический редирект на HTTPS'}
                else:
                    return {'score': 5, 'max_score': 10, 'status': '⚠️ Не настроен',
                            'details': 'Редирект на HTTPS не настроен'}
            else:
                return {'score': 0, 'max_score': 10, 'status': '❌ HTTP',
                        'details': 'Сайт использует HTTP вместо HTTPS'}

        except Exception:
            return {'score': 5, 'max_score': 10, 'status': '⚠️ Не проверено',
                    'details': 'Не удалось проверить редиректы'}

    def update_results_ui(self):
        """Обновление UI с результатами"""
        score = self.safety_score
        self.score_value.config(text=str(score))

        if score >= 85:
            color = self.colors['excellent']
            risk_text = "ОЧЕНЬ НИЗКИЙ"
        elif score >= 70:
            color = self.colors['good']
            risk_text = "НИЗКИЙ"
        elif score >= 55:
            color = self.colors['medium']
            risk_text = "СРЕДНИЙ"
        elif score >= 40:
            color = self.colors['poor']
            risk_text = "ВЫСОКИЙ"
        else:
            color = self.colors['critical']
            risk_text = "ОЧЕНЬ ВЫСОКИЙ"

        self.score_value.config(fg=color)
        self.risk_label.config(text=f"Уровень риска: {risk_text}", fg=color)

        # Рисуем круговой индикатор
        self.draw_score_circle(score, color)

        # Добавляем проверки в таблицу
        for check in self.analysis_results['checks']:
            self.security_tree.insert('', 'end',
                                      values=(check['name'], check['status'],
                                              f"{check['score']}/{check['max_score']}",
                                              check['details']))

        # Обновляем метрики
        categories = {
            'security': ['Доступность сайта', 'HTTPS протокол', 'SSL сертификат',
                         'Заголовки безопасности', 'Безопасность контента',
                         'DNS записи', 'HTTP редиректы'],
            'authenticity': ['Безопасность домена', 'Проверка на фишинг'],
            'performance': ['Производительность'],
            'quality': ['Структура сайта']
        }

        for category, check_names in categories.items():
            cat_checks = [c for c in self.analysis_results['checks'] if c['name'] in check_names]
            if cat_checks:
                total_score = sum(c['score'] for c in cat_checks)
                total_max = sum(c['max_score'] for c in cat_checks)
                percentage = (total_score / total_max * 100) if total_max > 0 else 0

                label = getattr(self, f"{category}_score_label")
                label.config(text=f"{total_score}/{total_max}")

                progress = getattr(self, f"{category}_score_progress")
                progress['value'] = percentage

        # Обновляем сводку
        self.update_summary()

    def draw_score_circle(self, score, color):
        """Рисование кругового индикатора"""
        self.score_canvas.delete("all")

        center_x, center_y = 75, 75
        radius = 60

        # Фон
        self.score_canvas.create_oval(
            center_x - radius, center_y - radius,
            center_x + radius, center_y + radius,
            fill='#f8f9fa', outline='#dee2e6', width=2
        )

        # Прогресс
        angle = (score / 100) * 360
        self.score_canvas.create_arc(
            center_x - radius + 8, center_y - radius + 8,
            center_x + radius - 8, center_y + radius - 8,
            start=90, extent=-angle,
            fill=color, outline=color, width=10,
            style=tk.ARC
        )

        # Текст
        self.score_canvas.create_text(
            center_x, center_y,
            text=f"{score}",
            font=("Arial", 24, "bold"),
            fill=color
        )

        self.score_canvas.create_text(
            center_x, center_y + 20,
            text="баллов",
            font=("Arial", 9),
            fill=self.colors['gray']
        )

    def update_summary(self):
        """Обновление сводки"""
        self.summary_text.delete(1.0, tk.END)

        url = self.analysis_results['url']
        score = self.safety_score

        self.summary_text.insert(tk.END, "📊 СВОДКА АНАЛИЗА\n")
        self.summary_text.insert(tk.END, "=" * 50 + "\n\n")

        self.summary_text.insert(tk.END, f"🌐 Анализируемый сайт: {url}\n")
        self.summary_text.insert(tk.END, f"⏰ Время анализа: {self.analysis_results['timestamp']}\n")
        self.summary_text.insert(tk.END, f"🏆 Итоговая оценка: {score}/100\n\n")

        if score >= 85:
            self.summary_text.insert(tk.END, "✅ ОТЛИЧНЫЙ УРОВЕНЬ БЕЗОПАСНОСТИ\n")
            self.summary_text.insert(tk.END, "Сайт безопасен для использования.\n")
        elif score >= 70:
            self.summary_text.insert(tk.END, "⚠️  ХОРОШИЙ УРОВЕНЬ БЕЗОПАСНОСТИ\n")
            self.summary_text.insert(tk.END, "Сайт достаточно безопасен.\n")
        elif score >= 55:
            self.summary_text.insert(tk.END, "⚠️  СРЕДНИЙ УРОВЕНЬ БЕЗОПАСНОСТИ\n")
            self.summary_text.insert(tk.END, "Требуется осторожность.\n")
        elif score >= 40:
            self.summary_text.insert(tk.END, "❌ НИЗКИЙ УРОВЕНЬ БЕЗОПАСНОСТИ\n")
            self.summary_text.insert(tk.END, "Избегайте ввода личных данных.\n")
        else:
            self.summary_text.insert(tk.END, "❌ КРИТИЧЕСКИЙ УРОВЕНЬ РИСКА\n")
            self.summary_text.insert(tk.END, "Сайт представляет угрозу безопасности.\n")

    def update_site_info_tab(self):
        """Обновление информации о сайте"""
        self.site_info_text.delete(1.0, tk.END)
        self.content_analysis_text.delete(1.0, tk.END)

        if not self.site_content_analysis:
            return

        info = self.site_content_analysis

        # Основная информация
        self.site_info_text.insert(tk.END, "📋 ОСНОВНАЯ ИНФОРМАЦИЯ\n")
        self.site_info_text.insert(tk.END, "=" * 40 + "\n\n")

        self.site_info_text.insert(tk.END, f"📄 Заголовок: {info.get('title')}\n\n")
        self.site_info_text.insert(tk.END, f"📝 Описание: {info.get('description')}\n\n")
        self.site_info_text.insert(tk.END, f"🏷️ Тип сайта: {info.get('site_type')}\n")
        self.site_info_text.insert(tk.END, f"🖼️ Изображений: {info.get('images_count')}\n")
        self.site_info_text.insert(tk.END, f"📏 Размер страницы: {info.get('page_size_kb', 0):.1f} KB\n")

        # Анализ контента
        self.content_analysis_text.insert(tk.END, "📊 АНАЛИЗ КОНТЕНТА\n")
        self.content_analysis_text.insert(tk.END, "=" * 40 + "\n\n")

        site_type = info.get('site_type', '')
        if 'магазин' in site_type.lower():
            self.content_analysis_text.insert(tk.END, "🛒 ИНТЕРНЕТ-МАГАЗИН\n")
            self.content_analysis_text.insert(tk.END, "• Проверьте SSL для оплаты\n")
            self.content_analysis_text.insert(tk.END, "• Убедитесь в наличии контактов\n")
            self.content_analysis_text.insert(tk.END, "• Читайте отзывы о магазине\n")
        elif 'новост' in site_type.lower():
            self.content_analysis_text.insert(tk.END, "📰 НОВОСТНОЙ САЙт\n")
            self.content_analysis_text.insert(tk.END, "• Проверьте источник новостей\n")
            self.content_analysis_text.insert(tk.END, "• Сравните с другими СМИ\n")
            self.content_analysis_text.insert(tk.END, "• Проверьте даты публикаций\n")
        else:
            self.content_analysis_text.insert(tk.END, "ℹ️ ИНФОРМАЦИОННЫЙ САЙТ\n")
            self.content_analysis_text.insert(tk.END, "• Проверьте актуальность информации\n")
            self.content_analysis_text.insert(tk.END, "• Оцените качество контента\n")
            self.content_analysis_text.insert(tk.END, "• Ищите контактные данные\n")

    def update_authenticity_info(self, domain, checks):
        """Обновление информации об аутентичности"""
        self.clone_text.delete(1.0, tk.END)
        self.domain_text.delete(1.0, tk.END)

        # Находим проверки аутентичности
        auth_checks = [c for c in checks if c['category'] == 'authenticity']
        if not auth_checks:
            return

        total_score = sum(c['score'] for c in auth_checks)
        total_max = sum(c['max_score'] for c in auth_checks)
        auth_percentage = (total_score / total_max * 100) if total_max > 0 else 0

        self.clone_text.insert(tk.END, "🕵️ АНАЛИЗ АУТЕНТИЧНОСТИ\n")
        self.clone_text.insert(tk.END, "=" * 50 + "\n\n")

        if auth_percentage >= 80:
            self.clone_text.insert(tk.END, "✅ ВЫСОКАЯ АУТЕНТИЧНОСТЬ\n\n")
            self.clone_text.insert(tk.END, "Сайт выглядит легитимным.\n")
            self.authenticity_indicator.config(text="🔍 АУТЕНТИЧНОСТЬ: ВЫСОКАЯ", fg=self.colors['success'])
        elif auth_percentage >= 60:
            self.clone_text.insert(tk.END, "⚠️  СРЕДНЯЯ АУТЕНТИЧНОСТЬ\n\n")
            self.clone_text.insert(tk.END, "Имеются незначительные подозрения.\n")
            self.authenticity_indicator.config(text="🔍 АУТЕНТИЧНОСТЬ: СРЕДНЯЯ", fg=self.colors['warning'])
        else:
            self.clone_text.insert(tk.END, "❌ НИЗКАЯ АУТЕНТИЧНОСТЬ\n\n")
            self.clone_text.insert(tk.END, "Высокий риск фишинга.\n")
            self.authenticity_indicator.config(text="🔍 АУТЕНТИЧНОСТЬ: НИЗКАЯ", fg=self.colors['danger'])

        # Доменная информация
        extracted = tldextract.extract(domain)
        self.domain_text.insert(tk.END, "🌐 ИНФОРМАЦИЯ О ДОМЕНЕ\n")
        self.domain_text.insert(tk.END, "=" * 50 + "\n\n")

        self.domain_text.insert(tk.END, f"• Домен: {extracted.domain}.{extracted.suffix}\n")
        self.domain_text.insert(tk.END, f"• Основное имя: {extracted.domain}\n")
        self.domain_text.insert(tk.END, f"• TLD: .{extracted.suffix}\n")
        self.domain_text.insert(tk.END, f"• Поддомен: {extracted.subdomain if extracted.subdomain else 'нет'}\n")

    def generate_reports(self):
        """Генерация отчетов"""
        self.generate_performance_report()
        self.generate_recommendations_report()

    def generate_performance_report(self):
        """Генерация отчета о производительности"""
        self.performance_text.delete(1.0, tk.END)

        self.performance_text.insert(tk.END, "⚡ ОТЧЕТ О ПРОИЗВОДИТЕЛЬНОСТИ\n")
        self.performance_text.insert(tk.END, "=" * 60 + "\n\n")

        perf_checks = [c for c in self.analysis_results.get('checks', [])
                       if c.get('category') == 'performance']

        for check in perf_checks:
            self.performance_text.insert(tk.END, f"📊 {check['name']}:\n")
            self.performance_text.insert(tk.END, f"   Оценка: {check['score']}/{check['max_score']}\n")
            self.performance_text.insert(tk.END, f"   Статус: {check['status']}\n")
            self.performance_text.insert(tk.END, f"   Детали: {check['details']}\n\n")

        self.performance_text.insert(tk.END, "💡 СОВЕТЫ ПО ОПТИМИЗАЦИИ:\n")
        self.performance_text.insert(tk.END, "-" * 40 + "\n")

        slow_checks = [c for c in perf_checks if c['score'] < c['max_score'] * 0.7]
        if slow_checks:
            self.performance_text.insert(tk.END, "Для улучшения скорости:\n")
            self.performance_text.insert(tk.END, "• Включите сжатие GZIP\n")
            self.performance_text.insert(tk.END, "• Используйте кэширование\n")
            self.performance_text.insert(tk.END, "• Оптимизируйте изображения\n")
        else:
            self.performance_text.insert(tk.END, "Производительность в норме.\n")

    def generate_recommendations_report(self):
        """Генерация отчета с рекомендациями"""
        self.recommendations_text.delete(1.0, tk.END)

        self.recommendations_text.insert(tk.END, "💡 РЕКОМЕНДАЦИИ ПО БЕЗОПАСНОСТИ\n")
        self.recommendations_text.insert(tk.END, "=" * 60 + "\n\n")

        score = self.safety_score

        if score >= 85:
            self.recommendations_text.insert(tk.END, "✅ ОТЛИЧНАЯ БЕЗОПАСНОСТЬ\n\n")
            self.recommendations_text.insert(tk.END, "Рекомендации:\n")
            self.recommendations_text.insert(tk.END, "• Продолжайте поддерживать высокий уровень\n")
            self.recommendations_text.insert(tk.END, "• Регулярно обновляйте SSL\n")
            self.recommendations_text.insert(tk.END, "• Мониторьте безопасность\n")
        elif score >= 70:
            self.recommendations_text.insert(tk.END, "⚠️  ХОРОШАЯ БЕЗОПАСНОСТЬ\n\n")
            self.recommendations_text.insert(tk.END, "Рекомендации:\n")
            self.recommendations_text.insert(tk.END, "• Улучшите заголовки безопасности\n")
            self.recommendations_text.insert(tk.END, "• Настройте редиректы\n")
            self.recommendations_text.insert(tk.END, "• Проверьте SSL настройки\n")
        elif score >= 55:
            self.recommendations_text.insert(tk.END, "⚠️  СРЕДНЯЯ БЕЗОПАСНОСТЬ\n\n")
            self.recommendations_text.insert(tk.END, "Рекомендации:\n")
            self.recommendations_text.insert(tk.END, "• Обязательно перейдите на HTTPS\n")
            self.recommendations_text.insert(tk.END, "• Настройте базовые заголовки\n")
            self.recommendations_text.insert(tk.END, "• Проверьте домен на фишинг\n")
        else:
            self.recommendations_text.insert(tk.END, "❌ НИЗКАЯ БЕЗОПАСНОСТЬ\n\n")
            self.recommendations_text.insert(tk.END, "СРОЧНЫЕ РЕКОМЕНДАЦИИ:\n")
            self.recommendations_text.insert(tk.END, "• НЕМЕДЛЕННО настройте HTTPS\n")
            self.recommendations_text.insert(tk.END, "• Проверьте домен на легитимность\n")
            self.recommendations_text.insert(tk.END, "• Обратитесь к специалистам\n")

        # Специфические рекомендации
        checks = self.analysis_results.get('checks', [])
        problems = [c for c in checks if c['score'] < c['max_score'] * 0.6]

        if problems:
            self.recommendations_text.insert(tk.END, "\n🔧 ПРОБЛЕМЫ ДЛЯ ИСПРАВЛЕНИЯ:\n")
            self.recommendations_text.insert(tk.END, "-" * 40 + "\n")

            for check in problems[:3]:
                self.recommendations_text.insert(tk.END, f"• {check['name']}: {check['details']}\n")

    def update_status(self, message):
        """Обновление статуса"""
        self.root.after(0, lambda: self.status_label.config(text=message))

    def show_error(self, message):
        """Показать ошибку"""
        self.root.after(0, lambda: messagebox.showerror("Ошибка", message))

    def analysis_complete(self):
        """Завершение анализа"""
        self.is_analyzing = False
        self.progress.stop()
        self.analyze_button.config(state=tk.NORMAL, text="🚀 АНАЛИЗИРОВАТЬ")
        self.status_label.config(text="Анализ завершен")
        self.notebook.select(0)


def main():
    root = tk.Tk()

    style = ttk.Style()
    style.theme_use('clam')

    app = WebsiteSecurityAnalyzer(root)
    root.mainloop()


if __name__ == "__main__":
    print("=" * 60)
    print("🔐 АНАЛИЗАТОР БЕЗОПАСНОСТИ САЙТОВ")
    print("=" * 60)
    print("\n📦 Установите зависимости:")
    print("pip install requests beautifulsoup4 tldextract dnspython")
    print("\n✅ Готов к работе!")

    main()
