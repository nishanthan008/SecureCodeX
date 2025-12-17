from setuptools import setup, find_packages
import os

# Read README for long description
def read_file(filename):
    filepath = os.path.join(os.path.dirname(__file__), filename)
    if os.path.exists(filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read()
    return ''

setup(
    name='securecodex-cli',
    version='1.0.0',
    description='Security Source Code Analysis Tool - CLI Edition',
    long_description=read_file('README_CLI.md'),
    long_description_content_type='text/markdown',
    author='SecureCodeX Team',
    author_email='',
    url='https://github.com/yourusername/SecureCodeX',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'sqlalchemy>=1.4.0',
        'reportlab>=3.6.0',
        'tqdm>=4.60.0',
        'colorama>=0.4.4',
        # Multi-language parsing and AST analysis
        'esprima>=4.0.1',
        'javalang>=0.13.0',
        'tree-sitter>=0.20.0',
        'packaging>=21.0',
        'pyyaml>=6.0',
        'toml>=0.10.2',
        # Enhanced security scanning
        'python-magic>=0.4.27',
        'chardet>=5.0.0',
    ],
    entry_points={
        'console_scripts': [
            'securecodex=securecodex.cli:main',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: Security',
        'Topic :: Software Development :: Quality Assurance',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.8',
    keywords='security vulnerability scanner static-analysis code-analysis',
)
