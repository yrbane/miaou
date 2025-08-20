#!/usr/bin/env python3
"""
Générateur de glossaire HTML interactif pour Miaou

Convertit le fichier GLOSSAIRE.md en une page HTML interactive avec :
- Liens internes automatiques entre termes
- Recherche en temps réel avec défilement automatique
- Interface wiki-like sur une seule page
- Style moderne et responsive
"""

import re
import os
import sys
from pathlib import Path

class GlossaryGenerator:
    def __init__(self, glossary_path, output_path):
        self.glossary_path = Path(glossary_path)
        self.output_path = Path(output_path)
        self.terms = {}
        self.sections = {}
        
    def parse_glossary(self):
        """Parse le fichier glossaire markdown et extrait les termes"""
        print(f"📖 Parsing du glossaire : {self.glossary_path}")
        
        with open(self.glossary_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Extraire les sections principales
        current_section = None
        current_term = None
        current_definition = []
        
        lines = content.split('\n')
        for line in lines:
            # Détection des sections (## Section)
            if line.startswith('## '):
                if current_term:
                    self.terms[current_term] = {
                        'definition': '\n'.join(current_definition).strip(),
                        'section': current_section
                    }
                current_section = line[3:].strip()
                self.sections[current_section] = []
                current_term = None
                current_definition = []
                continue
            
            # Détection des termes (### **Terme**)
            if line.startswith('### **') and line.endswith('**'):
                if current_term:
                    self.terms[current_term] = {
                        'definition': '\n'.join(current_definition).strip(),
                        'section': current_section
                    }
                
                current_term = line[6:-2]  # Enlever ### ** et **
                current_definition = []
                if current_section:
                    self.sections[current_section].append(current_term)
                continue
            
            # Accumulation de la définition
            if current_term:
                current_definition.append(line)
        
        # Dernier terme
        if current_term:
            self.terms[current_term] = {
                'definition': '\n'.join(current_definition).strip(),
                'section': current_section
            }
        
        print(f"✅ {len(self.terms)} termes extraits dans {len(self.sections)} sections")
    
    def create_term_links(self, text):
        """Crée des liens automatiques vers les termes du glossaire"""
        # Créer une regex pour tous les termes, triés par longueur décroissante
        # pour éviter que des termes courts remplacent des parties de termes longs
        terms_sorted = sorted(self.terms.keys(), key=len, reverse=True)
        
        for term in terms_sorted:
            # Éviter les auto-références dans les définitions du même terme
            if f'id="{self.create_id(term)}"' in text:
                continue
                
            # Créer un pattern qui évite les remplacements dans les liens existants
            pattern = rf'\b{re.escape(term)}\b(?![^<]*>)(?![^<]*</a>)'
            replacement = f'<a href="#{self.create_id(term)}" class="term-link">{term}</a>'
            text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
        
        return text
    
    def create_id(self, term):
        """Crée un ID HTML valide à partir d'un terme"""
        # Remplacer caractères spéciaux par des tirets
        term_id = re.sub(r'[^a-zA-Z0-9\s]', '', term.lower())
        term_id = re.sub(r'\s+', '-', term_id.strip())
        return term_id
    
    def generate_html(self):
        """Génère le fichier HTML complet"""
        print(f"🎨 Génération du HTML : {self.output_path}")
        
        # Structure HTML de base
        html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Glossaire Technique Miaou - Wiki Interactif</title>
    <style>
        {self.get_css()}
    </style>
</head>
<body>
    <div class="glossary-container">
        <header class="glossary-header">
            <h1>📚 Glossaire Technique Miaou</h1>
            <p class="subtitle">Wiki interactif des termes techniques</p>
            <div class="search-container">
                <input type="text" id="search" placeholder="🔍 Rechercher un terme..." autocomplete="off">
                <div class="search-stats">
                    <span id="search-results">0 résultats</span>
                </div>
            </div>
        </header>
        
        <nav class="sections-nav">
            <h3>📑 Sections</h3>
            <ul>
"""
        
        # Générer la navigation par sections
        for section in self.sections:
            if self.sections[section]:  # Seulement si la section a des termes
                section_id = self.create_id(section)
                term_count = len(self.sections[section])
                html += f'                <li><a href="#{section_id}" class="section-link">{section} <span class="term-count">({term_count})</span></a></li>\n'
        
        html += """            </ul>
        </nav>
        
        <main class="glossary-content">
"""
        
        # Générer le contenu par sections
        for section in self.sections:
            if not self.sections[section]:  # Skip empty sections
                continue
                
            section_id = self.create_id(section)
            html += f"""
            <section class="section" id="{section_id}">
                <h2>{section}</h2>
                <div class="terms-grid">
"""
            
            for term in self.sections[section]:
                if term not in self.terms:
                    continue
                    
                term_id = self.create_id(term)
                definition = self.terms[term]['definition']
                
                # Créer des liens automatiques dans la définition
                definition_with_links = self.create_term_links(definition)
                
                # Convertir markdown simple en HTML
                definition_with_links = self.simple_markdown_to_html(definition_with_links)
                
                html += f"""
                    <div class="term-card" id="{term_id}" data-term="{term.lower()}">
                        <h3 class="term-title">
                            <strong>{term}</strong>
                            <a href="#{term_id}" class="permalink" title="Lien permanent">#</a>
                        </h3>
                        <div class="term-definition">
                            {definition_with_links}
                        </div>
                    </div>
"""
            
            html += """                </div>
            </section>
"""
        
        # Footer et scripts
        html += f"""
        </main>
        
        <footer class="glossary-footer">
            <p>📊 <strong>{len(self.terms)}</strong> termes dans <strong>{len([s for s in self.sections if self.sections[s]])}</strong> sections</p>
            <p>Généré automatiquement depuis <code>docs/GLOSSAIRE.md</code></p>
            <p class="miaou-signature">🐱 <strong>Miaou v0.1.0</strong> - Glossaire Technique</p>
        </footer>
    </div>
    
    <script>
        {self.get_javascript()}
    </script>
</body>
</html>"""
        
        # Écrire le fichier
        with open(self.output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        print(f"✅ Glossaire HTML généré avec succès : {self.output_path}")
    
    def simple_markdown_to_html(self, text):
        """Convertit du markdown simple en HTML"""
        # Gras **texte**
        text = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', text)
        # Italique *texte*
        text = re.sub(r'\*(.*?)\*', r'<em>\1</em>', text)
        # Code `code`
        text = re.sub(r'`(.*?)`', r'<code>\1</code>', text)
        # Paragraphes
        text = re.sub(r'\n\s*\n', '</p><p>', text)
        if text and not text.startswith('<p>'):
            text = '<p>' + text + '</p>'
        return text
    
    def get_css(self):
        """Retourne le CSS pour la page"""
        return """
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #2c3e50;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        
        .glossary-container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            min-height: 100vh;
        }
        
        .glossary-header {
            background: linear-gradient(135deg, #2c3e50 0%, #3498db 100%);
            color: white;
            padding: 2rem;
            text-align: center;
            position: sticky;
            top: 0;
            z-index: 100;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .glossary-header h1 {
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
            font-weight: 700;
        }
        
        .subtitle {
            font-size: 1.2rem;
            opacity: 0.9;
            margin-bottom: 1.5rem;
        }
        
        .search-container {
            max-width: 600px;
            margin: 0 auto;
            position: relative;
        }
        
        #search {
            width: 100%;
            padding: 1rem 1.5rem;
            font-size: 1.1rem;
            border: none;
            border-radius: 50px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            outline: none;
            background: white;
        }
        
        #search:focus {
            box-shadow: 0 4px 20px rgba(0,0,0,0.2);
            transform: translateY(-1px);
        }
        
        .search-stats {
            text-align: center;
            margin-top: 0.5rem;
            font-size: 0.9rem;
            opacity: 0.8;
        }
        
        .sections-nav {
            background: #f8f9fa;
            border-bottom: 1px solid #e9ecef;
            padding: 1rem 2rem;
            position: sticky;
            top: 120px;
            z-index: 90;
        }
        
        .sections-nav h3 {
            margin-bottom: 1rem;
            color: #495057;
        }
        
        .sections-nav ul {
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
            list-style: none;
        }
        
        .section-link {
            display: inline-block;
            padding: 0.5rem 1rem;
            background: white;
            color: #495057;
            text-decoration: none;
            border-radius: 20px;
            border: 1px solid #dee2e6;
            transition: all 0.3s ease;
        }
        
        .section-link:hover {
            background: #3498db;
            color: white;
            transform: translateY(-1px);
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        
        .term-count {
            font-size: 0.8rem;
            opacity: 0.7;
        }
        
        .glossary-content {
            padding: 2rem;
        }
        
        .section {
            margin-bottom: 3rem;
        }
        
        .section h2 {
            color: #2c3e50;
            font-size: 2rem;
            margin-bottom: 1.5rem;
            border-bottom: 3px solid #3498db;
            padding-bottom: 0.5rem;
        }
        
        .terms-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 1.5rem;
        }
        
        .term-card {
            background: white;
            border-radius: 10px;
            padding: 1.5rem;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            border-left: 4px solid #3498db;
            transition: all 0.3s ease;
        }
        
        .term-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.15);
        }
        
        .term-card.highlight {
            background: #fff3cd;
            border-left-color: #ffc107;
            animation: highlight 1s ease-in-out;
        }
        
        @keyframes highlight {
            0%, 100% { background: #fff3cd; }
            50% { background: #ffecb3; }
        }
        
        .term-title {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
            color: #2c3e50;
            font-size: 1.3rem;
        }
        
        .permalink {
            color: #6c757d;
            text-decoration: none;
            opacity: 0;
            transition: opacity 0.3s ease;
        }
        
        .term-card:hover .permalink {
            opacity: 1;
        }
        
        .permalink:hover {
            color: #3498db;
        }
        
        .term-definition {
            color: #495057;
            line-height: 1.7;
        }
        
        .term-link {
            color: #3498db;
            text-decoration: none;
            font-weight: 500;
            border-bottom: 1px dotted #3498db;
            transition: all 0.3s ease;
        }
        
        .term-link:hover {
            color: #2980b9;
            border-bottom-style: solid;
        }
        
        .glossary-footer {
            background: #2c3e50;
            color: white;
            text-align: center;
            padding: 2rem;
            margin-top: 3rem;
        }
        
        .glossary-footer p {
            margin-bottom: 0.5rem;
        }
        
        .miaou-signature {
            font-size: 1.2rem;
            font-weight: bold;
            margin-top: 1rem !important;
        }
        
        .hidden {
            display: none !important;
        }
        
        code {
            background: #f8f9fa;
            padding: 0.2rem 0.4rem;
            border-radius: 3px;
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
        }
        
        strong {
            color: #2c3e50;
        }
        
        @media (max-width: 768px) {
            .glossary-header {
                padding: 1rem;
            }
            
            .glossary-header h1 {
                font-size: 2rem;
            }
            
            .sections-nav {
                padding: 1rem;
            }
            
            .sections-nav ul {
                justify-content: center;
            }
            
            .glossary-content {
                padding: 1rem;
            }
            
            .terms-grid {
                grid-template-columns: 1fr;
            }
        }
        """
    
    def get_javascript(self):
        """Retourne le JavaScript pour la recherche en temps réel"""
        return """
        class GlossarySearch {
            constructor() {
                this.searchInput = document.getElementById('search');
                this.searchResults = document.getElementById('search-results');
                this.allTerms = document.querySelectorAll('.term-card');
                this.allSections = document.querySelectorAll('.section');
                
                this.init();
            }
            
            init() {
                this.searchInput.addEventListener('input', (e) => {
                    this.performSearch(e.target.value);
                });
                
                // Recherche lors du chargement si hash présent
                if (window.location.hash) {
                    this.scrollToElement(window.location.hash);
                }
            }
            
            performSearch(query) {
                query = query.toLowerCase().trim();
                
                if (!query) {
                    this.showAllTerms();
                    return;
                }
                
                let visibleCount = 0;
                let firstMatch = null;
                
                this.allTerms.forEach(term => {
                    const termName = term.dataset.term;
                    const termContent = term.textContent.toLowerCase();
                    
                    if (termName.includes(query) || termContent.includes(query)) {
                        term.classList.remove('hidden');
                        term.parentElement.parentElement.classList.remove('hidden');
                        visibleCount++;
                        
                        if (!firstMatch && termName.includes(query)) {
                            firstMatch = term;
                        }
                    } else {
                        term.classList.add('hidden');
                    }
                });
                
                // Masquer sections vides
                this.allSections.forEach(section => {
                    const visibleTerms = section.querySelectorAll('.term-card:not(.hidden)');
                    if (visibleTerms.length === 0) {
                        section.classList.add('hidden');
                    } else {
                        section.classList.remove('hidden');
                    }
                });
                
                // Mettre à jour stats
                this.searchResults.textContent = `${visibleCount} résultat${visibleCount > 1 ? 's' : ''}`;
                
                // Scroll au premier résultat exact
                if (firstMatch && query.length > 2) {
                    this.scrollToElement('#' + firstMatch.id, true);
                }
            }
            
            showAllTerms() {
                this.allTerms.forEach(term => term.classList.remove('hidden'));
                this.allSections.forEach(section => section.classList.remove('hidden'));
                this.searchResults.textContent = `${this.allTerms.length} termes`;
            }
            
            scrollToElement(selector, highlight = false) {
                const element = document.querySelector(selector);
                if (element) {
                    element.scrollIntoView({ 
                        behavior: 'smooth', 
                        block: 'center' 
                    });
                    
                    if (highlight) {
                        element.classList.add('highlight');
                        setTimeout(() => {
                            element.classList.remove('highlight');
                        }, 2000);
                    }
                }
            }
        }
        
        // Initialisation
        document.addEventListener('DOMContentLoaded', () => {
            new GlossarySearch();
            
            // Stats initiales
            const termCount = document.querySelectorAll('.term-card').length;
            document.getElementById('search-results').textContent = `${termCount} termes`;
        });
        
        // Gestion des liens permaliens
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('permalink')) {
                e.preventDefault();
                const targetId = e.target.getAttribute('href');
                window.location.hash = targetId;
                
                const targetElement = document.querySelector(targetId);
                if (targetElement) {
                    targetElement.scrollIntoView({ 
                        behavior: 'smooth', 
                        block: 'center' 
                    });
                    targetElement.classList.add('highlight');
                    setTimeout(() => {
                        targetElement.classList.remove('highlight');
                    }, 2000);
                }
            }
        });
        """

def main():
    """Fonction principale"""
    # Détecter le répertoire racine du projet
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    
    glossary_path = project_root / 'docs' / 'GLOSSAIRE.md'
    output_path = script_dir / 'glossaire.html'
    
    if not glossary_path.exists():
        print(f"❌ Fichier glossaire introuvable : {glossary_path}")
        sys.exit(1)
    
    print("🚀 Génération du glossaire HTML interactif Miaou")
    print(f"📁 Projet : {project_root}")
    print(f"📖 Source : {glossary_path}")
    print(f"🎯 Destination : {output_path}")
    print()
    
    generator = GlossaryGenerator(glossary_path, output_path)
    generator.parse_glossary()
    generator.generate_html()
    
    print()
    print("🎉 Génération terminée avec succès !")
    print(f"👀 Ouvrez {output_path} dans votre navigateur")
    print()
    print("🔗 Fonctionnalités :")
    print("   • Recherche en temps réel")
    print("   • Liens automatiques entre termes")
    print("   • Navigation par sections")
    print("   • Interface responsive")
    print("   • Liens permanents")

if __name__ == "__main__":
    main()