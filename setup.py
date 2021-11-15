from pathlib import Path
from setuptools import setup

version = Path("Jira-Lens/_version.py").read_text(encoding="utf-8")
about = {}
exec(version, about)

setup(name='Jira-Lens',
      #version=__import__('Jira-Lens').__version__,
      version=about["__version__"],
      description='Jira-Lens : JIRA Security Auditing Tool',
      author='Mayank Pandey',
      author_email='mayankraj956@gmail.com',
      url='https://github.com/MayankPandey01/Jira-Lens/',
      long_description = file: README.md
      long_description_content_type = text/markdown
      download_url = 'https://github.com/MayankPandey01/Jira-Lens/archive/refs/tags/v1.0.0.tar.gz', 
      install_requires=["progressbar","requests","argparse","colorama"],
     
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],

    keywords=['Jira-Lens','JIRA','Auditing', 'bug bounty', 'http', 'pentesting', 'security'],

)
