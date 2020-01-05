# -*- CODING: UTF-8 -*-

# pylint: disable=invalid-name

import os
import sys

import sphinx_rtd_theme

# -- General configuration ------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    'sphinxcontrib.autohttp.flask',
]

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

# General information about the project.
project = 'Todoer'
copyright = '2016, Adam Dangoor'  # pylint: disable=redefined-builtin
author = 'Adam Dangoor'

# The version info for the project you're documenting, acts as replacement for
# |version| and |release|, also used in various other places throughout the
# built documents.
version = '0.1'
release = '0.1'

# If true, `todo` and `todoList` produce output, else they produce nothing.
todo_include_todos = False

# -- Options for HTML output ----------------------------------------------

html_theme = 'sphinx_rtd_theme'
html_theme_path = [sphinx_rtd_theme.get_html_theme_path()]

# If true, "Created using Sphinx" is shown in the HTML footer. Default is True.
html_show_sphinx = False

# If true, "(C) Copyright ..." is shown in the HTML footer. Default is True.
html_show_copyright = False

# Output file base name for HTML help builder.
htmlhelp_basename = 'todoerdoc'
