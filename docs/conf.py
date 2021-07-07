# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

project = "auditee"
copyright = "2021, Sylvain Bellemare, IC3 & Cornell University"
author = "Sylvain Bellemare"

release = "0.0.1.dev0"

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.coverage",
    "sphinx.ext.doctest",
    "sphinx.ext.intersphinx",
    "sphinx.ext.mathjax",
    "sphinx.ext.napoleon",
    "sphinx.ext.todo",
    "sphinx.ext.viewcode",
    "sphinxcontrib.bibtex",
    "sphinx_proof",
    "sphinx_togglebutton",
]

intersphinx_mapping = {"https://docs.python.org/": None}

# autodoc_default_options = {
#    "members": None,
#    "undoc-members": None,
#    "private-members": None,
#    "inherited-members": None,
#    # "show-inheritance": None,
# }

bibtex_bibfiles = ["refs.bib"]
todo_include_todos = True
templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

html_static_path = ["_static"]

# html_theme = "alabaster"
html_theme = "sphinx_book_theme"
html_title = "auditee"
html_logo = "_static/logo.svg"
html_theme_options = {
    "repository_url": "https://github.com/sbellem/auditee",
    "use_repository_button": True,
    "use_download_button": True,
    "use_fullscreen_button": True,
    #    "logo": "logo.svg",
    #    "logo_name": True,
    #    "description": "Tool for Intel SGX Enclaves",
    #    "github_user": "sbellem",
    #    "github_repo": "auditee",
    #    "fixed_sidebar": True,
    #    "page_width": "1100px",
}
