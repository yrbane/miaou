#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# Define paths
PROJECT_ROOT="/home/seb/Dev/miaou"
DOCS_DIR="$PROJECT_ROOT/docs"
WEB_DIR="$PROJECT_ROOT/mdbook"
TEMP_MDBOOK_DIR=$(mktemp -d -t mdbook-XXXXXXXXXX)

echo "--- Starting website generation ---"

# 1. Check for mdBook installation
if ! command -v mdbook &> /dev/null
then
    echo "mdBook could not be found. Please install it: cargo install mdbook"
    exit 1
fi

echo "mdBook found. Proceeding..."

# 2. Clean previous build
echo "Cleaning previous build in $WEB_DIR..."
rm -rf "$WEB_DIR"
mkdir -p "$WEB_DIR"

# 3. Initialize mdBook project in a temporary directory
echo "Initializing mdBook project in temporary directory: $TEMP_MDBOOK_DIR"
cd "$TEMP_MDBOOK_DIR"
mdbook init --force # Initialize, creating src/SUMMARY.md and src/chapter_1.md

# 4. Clean up default mdBook content before copying docs
echo "Cleaning up default mdBook content..."
rm "$TEMP_MDBOOK_DIR/src/SUMMARY.md"
rm "$TEMP_MDBOOK_DIR/src/chapter_1.md"

# 5. Copy docs content to mdBook's src directory
echo "Copying Markdown files from $DOCS_DIR to $TEMP_MDBOOK_DIR/src..."
cp -r "$DOCS_DIR/." "$TEMP_MDBOOK_DIR/src/"

# 6. Generate SUMMARY.md
echo "Generating SUMMARY.md..."
SUMMARY_FILE="$TEMP_MDBOOK_DIR/src/SUMMARY.md"

# Start SUMMARY.md with a title
echo "# Summary" > "$SUMMARY_FILE"
echo "" >> "$SUMMARY_FILE"

# Find all markdown files in the src directory (relative to src) and add them to SUMMARY.md
# Exclude SUMMARY.md itself
find "$TEMP_MDBOOK_DIR/src" -type f -name "*.md" | sort | while read -r file;
do
    # Get path relative to src directory
    relative_path="${file#"$TEMP_MDBOOK_DIR/src/"}"
    
    # Skip SUMMARY.md itself
    if [[ "$relative_path" == "SUMMARY.md" ]]; then
        continue
    fi

    # Extract filename without extension for the link text
    filename=$(basename -- "$relative_path")
    filename_no_ext="${filename%.*}"

    # Replace hyphens with spaces and capitalize first letter of each word for better readability
    display_name=$(echo "$filename_no_ext" | sed -r 's/[-_]/ /g' | awk '{for(i=1;i<=NF;i++) $i=toupper(substr($i,1,1))tolower(substr($i,2));}1')

    # Add entry to SUMMARY.md
    echo "- [$display_name]($relative_path)" >> "$SUMMARY_FILE"
done

# 7. Create book.toml configuration (without custom CSS/JS)
echo "Creating book.toml configuration..."
cat << EOF > "$TEMP_MDBOOK_DIR/book.toml"
[book]
title = "Miaou Documentation"
authors = ["Miaou Team"]
description = "Comprehensive documentation for the Miaou project."
language = "en"
multilingual = false
src = "src"

[output.html]
default-theme = "light"
preferred-dark-theme = "dark"
git-repository-url = "https://github.com/your-org/miaou" # Placeholder, update if needed
git-repository-icon = "fa-github"
edit-url-template = "https://github.com/your-org/miaou/edit/main/{path}" # Placeholder, update if needed
site-url = "/miaou/" # Base URL for the site, adjust if hosted under a subpath
cname = "docs.miaou.org" # Placeholder, update if needed

[output.html.print]
enable = true

[output.html.search]
enable = true
limit-results = 30
EOF

# 8. Build the book
echo "Building the book to $WEB_DIR..."
mdbook build --dest-dir "$WEB_DIR"

# 9. Clean up temporary directory
echo "Cleaning up temporary directory: $TEMP_MDBOOK_DIR"
rm -rf "$TEMP_MDBOOK_DIR"

echo "--- Website generation complete! ---"
echo "You can view your website by opening $WEB_DIR/index.html in your browser."
