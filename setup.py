"""Compatibility metadata for older pip editable installs."""

from setuptools import find_packages, setup


setup(
    name="stratatrace",
    version="0.4.0",
    description="Boundary-aware, confidence-bounded adaptive traceroute",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    license="Apache-2.0",
    python_requires=">=3.9",
    package_dir={"": "src"},
    packages=find_packages("src"),
    entry_points={"console_scripts": ["stratatrace=stratatrace.cli:main"]},
)
