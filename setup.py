"""
Package configuration for portscanner.
"""

from setuptools import setup, find_packages

with open("README.md", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="portscanner",
    version="1.0.0",
    author="Your Name",
    author_email="you@example.com",
    description="A professional Python TCP port scanner with banner grabbing and rich output",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/youruser/portscanner",
    license="MIT",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    python_requires=">=3.10",
    install_requires=[
        "tqdm>=4.66.0",
        "rich>=13.7.0",
    ],
    extras_require={
        "dev": [
            "pytest>=8.0",
            "pytest-cov>=5.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "portscanner=scanner.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: System :: Networking",
        "Topic :: Security",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
    ],
    keywords="port scanner network security tcp banner grabbing",
)
