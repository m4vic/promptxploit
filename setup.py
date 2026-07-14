from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="promptxploit",
    version="1.0.0",
    author="m4vic",
    author_email="sanskarmaheshwari062@gmail.com",
    description="LLM penetration testing framework - Discover vulnerabilities before attackers do",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/m4vic/promptxploit",
    project_urls={
        "Source": "https://github.com/m4vic/promptxploit",
        "Issues": "https://github.com/m4vic/promptxploit/issues",
    },
    packages=find_packages(include=["promptxploit", "promptxploit.*"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Software Development :: Testing",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=[
        "rich",       # terminal output
        "requests",   # HTTP API targets
        "datasets",   # --source hf (stream attacks from HuggingFace)
    ],
    extras_require={
        "openai": ["openai", "python-dotenv"],       # --judge openai
        "gemini": ["google-generativeai"],           # --judge gemini
        "dev": ["pytest", "black", "flake8"],
        # Local judging uses Ollama over HTTP — no Python dep needed.
    },
    include_package_data=True,
    entry_points={
        "console_scripts": [
            "promptxploit=promptxploit.cli:main",
        ],
    },
)
