# setup.py

from setuptools import setup, find_packages

setup(
    name="vinmap",
    version="1.0.0",
    author="Vince Vasile",
    author_email="computerscience@vinny-van-gogh.com",
    description="Multithreaded Nmap Scanner with XML Merging",
    long_description=open('README.md').read(),
    long_description_content_type="text/markdown",
    url="https://github.com/VinnyVanGogh/ViNmap_custom_nmap_scanner",
    packages=find_packages(),
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
        "License :: OSI Approved :: MIT License",
    ],
    python_requires='>=3.7',
    install_requires=[
        'python-nmap',
        'xmltodict',
    ],
    entry_points={
        'console_scripts': [
            'vinmap=vinmap.vinmap:main',
        ],
    },
)

