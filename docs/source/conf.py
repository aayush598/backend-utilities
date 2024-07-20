import os
import sys
sys.path.insert(0, os.path.abspath('../../'))  # Adjust the path to your project

# Extensions
extensions = [
    'sphinx.ext.autodoc',
    'sphinx_autodoc_typehints',
]

# Project information
project = 'Your Project Name'
author = 'Your Name'
version = '0.1'
release = '0.1'

# Paths
templates_path = ['_templates']
html_static_path = ['_static']
