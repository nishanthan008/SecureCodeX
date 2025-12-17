"""
Scanner Configuration Module

Centralized configuration for scanner behavior, performance tuning,
and feature toggles.
"""

import os
from typing import List

class ScannerConfig:
    """Configuration settings for the security scanner"""
    
    # File Processing Limits
    MAX_FILE_SIZE = int(os.getenv('SCANNER_MAX_FILE_SIZE', 100 * 1024 * 1024))  # 100MB default
    WARN_FILE_SIZE = int(os.getenv('SCANNER_WARN_FILE_SIZE', 10 * 1024 * 1024))  # 10MB warning
    CHUNK_SIZE = int(os.getenv('SCANNER_CHUNK_SIZE', 10 * 1024 * 1024))  # 10MB chunks
    CHUNK_OVERLAP = int(os.getenv('SCANNER_CHUNK_OVERLAP', 1024))  # 1KB overlap for multi-line patterns
    
    # Parallel Processing
    PARALLEL_WORKERS = int(os.getenv('SCANNER_PARALLEL_WORKERS', 4))  # CPU cores
    ENABLE_PARALLEL = os.getenv('SCANNER_ENABLE_PARALLEL', 'true').lower() == 'true'
    
    # Database Optimization
    BATCH_INSERT_SIZE = int(os.getenv('SCANNER_BATCH_INSERT_SIZE', 100))  # Findings per batch
    COMMIT_INTERVAL = int(os.getenv('SCANNER_COMMIT_INTERVAL', 500))  # Files between commits
    
    # Feature Toggles
    ENABLE_AST_ANALYSIS = os.getenv('SCANNER_ENABLE_AST', 'true').lower() == 'true'
    ENABLE_PATTERN_ANALYSIS = os.getenv('SCANNER_ENABLE_PATTERN', 'true').lower() == 'true'
    ENABLE_ADVANCED_PATTERNS = os.getenv('SCANNER_ENABLE_ADVANCED', 'true').lower() == 'true'
    ENABLE_DEPENDENCY_SCAN = os.getenv('SCANNER_ENABLE_DEPENDENCY', 'true').lower() == 'true'
    
    # File Filtering
    SKIP_BINARY_FILES = os.getenv('SCANNER_SKIP_BINARY', 'true').lower() == 'true'
    SKIP_HIDDEN_FILES = os.getenv('SCANNER_SKIP_HIDDEN', 'true').lower() == 'true'
    
    # Binary file extensions to skip
    BINARY_EXTENSIONS = {
        '.pyc', '.pyo', '.so', '.dll', '.exe', '.bin', '.obj', '.o',
        '.a', '.lib', '.dylib', '.class', '.jar', '.war', '.ear',
        '.zip', '.tar', '.gz', '.bz2', '.7z', '.rar', '.iso',
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.svg',
        '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.webm',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.woff', '.woff2', '.ttf', '.eot', '.otf'
    }
    
    # Large file extensions (use streaming)
    LARGE_FILE_EXTENSIONS = {
        '.log', '.txt', '.csv', '.json', '.xml', '.sql', '.md'
    }
    
    # Directories to skip
    SKIP_DIRECTORIES = {
        '.git', '.svn', '.hg', '.bzr',
        'node_modules', 'bower_components',
        '__pycache__', '.pytest_cache', '.tox',
        'venv', 'env', '.env', 'virtualenv',
        'dist', 'build', 'target', 'out',
        '.idea', '.vscode', '.vs',
        'vendor', 'packages'
    }
    
    # Progress Update Interval
    PROGRESS_UPDATE_INTERVAL = int(os.getenv('SCANNER_PROGRESS_INTERVAL', 10))  # Files between updates
    
    @classmethod
    def is_binary_file(cls, file_path: str) -> bool:
        """Check if file is binary based on extension"""
        ext = os.path.splitext(file_path)[1].lower()
        return ext in cls.BINARY_EXTENSIONS
    
    @classmethod
    def should_skip_directory(cls, dir_name: str) -> bool:
        """Check if directory should be skipped"""
        return dir_name in cls.SKIP_DIRECTORIES or dir_name.startswith('.')
    
    @classmethod
    def should_use_streaming(cls, file_path: str, file_size: int) -> bool:
        """Determine if file should use streaming based on size or extension"""
        ext = os.path.splitext(file_path)[1].lower()
        return file_size > cls.CHUNK_SIZE or ext in cls.LARGE_FILE_EXTENSIONS
    
    @classmethod
    def get_config_summary(cls) -> dict:
        """Get current configuration as dictionary"""
        return {
            'max_file_size_mb': cls.MAX_FILE_SIZE / (1024 * 1024),
            'chunk_size_mb': cls.CHUNK_SIZE / (1024 * 1024),
            'parallel_workers': cls.PARALLEL_WORKERS,
            'parallel_enabled': cls.ENABLE_PARALLEL,
            'batch_insert_size': cls.BATCH_INSERT_SIZE,
            'ast_analysis': cls.ENABLE_AST_ANALYSIS,
            'pattern_analysis': cls.ENABLE_PATTERN_ANALYSIS,
            'advanced_patterns': cls.ENABLE_ADVANCED_PATTERNS,
            'dependency_scan': cls.ENABLE_DEPENDENCY_SCAN,
            'skip_binary': cls.SKIP_BINARY_FILES,
            'skip_hidden': cls.SKIP_HIDDEN_FILES
        }
