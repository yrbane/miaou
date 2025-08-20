# Scripts Miaou

Collection d'outils et scripts utilitaires pour le projet Miaou.

## 📜 Scripts disponibles

### `generate_glossary_html.py`
**Générateur de glossaire HTML interactif**

Convertit le fichier `docs/GLOSSAIRE.md` en une page HTML interactive avec recherche en temps réel et liens internes automatiques.

**Usage :**
```bash
python3 scripts/generate_glossary_html.py
```

**Fonctionnalités :**
- 🔍 **Recherche en temps réel** : Filtrage instantané des termes à chaque frappe
- 🔗 **Liens automatiques** : Chaque terme mentionné devient un lien cliquable
- 📑 **Navigation par sections** : Accès rapide aux différentes catégories
- 📱 **Interface responsive** : Optimisé pour desktop et mobile  
- 🎯 **Liens permanents** : URLs partageable pour chaque terme
- 🎨 **Design moderne** : Interface wiki élégante et professionnelle

**Sortie :** `scripts/glossaire.html` (99 termes dans 24 sections)

### `pre-commit.sh` 
**Hook pre-commit Git**

Script de validation automatique avant chaque commit.

**Usage :**
```bash
# Installation du hook
cp scripts/pre-commit.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

## 🔧 Développement

### Ajout de nouveaux scripts

1. Créer le script dans `scripts/`
2. Le rendre exécutable : `chmod +x scripts/mon_script.py`
3. Ajouter la documentation dans ce README
4. Tester le script localement

### Standards de code

- **Python** : PEP 8, type hints recommandés
- **Shell** : Compatible bash, utiliser `set -euo pipefail`
- **Documentation** : Docstrings et commentaires explicites
- **Gestion d'erreurs** : Codes de retour appropriés

## 🚀 Scripts futurs prévus

- `build_docs.py` - Génération complète de la documentation
- `release.py` - Automatisation des releases
- `test_coverage.py` - Rapports de couverture de tests
- `security_audit.py` - Audit de sécurité automatisé
- `benchmark.py` - Scripts de benchmarking automatisé

---

*Tous les scripts respectent la philosophie Miaou : sécurité, simplicité et efficacité.* 🐱