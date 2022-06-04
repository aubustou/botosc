from setuptools import setup

setup(
    name="botosc",
    version="0.6",
    packages=["botosc", "botosc_gen"],
    url="",
    license="MIT",
    author="Aubustou",
    author_email="survivalfr@yahoo.fr",
    description="Get dataclass objects out of Outscale API",
    install_requires=[
        "requests",
        "apischema",
        "pyYAML",
        "osc-sdk",
    ],
    python_requires=">=3.9",
)
