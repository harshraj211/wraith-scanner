"""Setup script for VulnScanner - Professional Vulnerability Assessment Tool."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="vulnscanner",
    version="1.0.0",
    author="Harsh Raj",
    author_email="harshraj84068@gmail.com",
    description="Professional web vulnerability scanner with CLI and web interface",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/harshraj211/vulnerability-scanner.git",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.28.0",
        "beautifulsoup4>=4.11.0",
        "reportlab>=3.6.0",
        "colorama>=0.4.6",
        "flask>=2.3.0",
        "flask-cors>=4.0.0",
        "flask-socketio>=5.3.0",
        "playwright>=1.40.0",
        "aiohttp>=3.9.0",
        "websockets>=12.0",
        "semgrep>=1.0.0",
    ],
    entry_points={
        "console_scripts": [
            "vulnscan=main:main",
        ],
    },
    include_package_data=True,
)
