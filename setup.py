from setuptools import setup, find_packages # type: ignore

setup(
    name="aegisscan",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        'requests==2.31.0',
        'beautifulsoup4==4.12.2',
        'argparse==1.4.0',
    ],
    entry_points={
        'console_scripts': [
            'aegisscan=security_scanner:main',
        ],
    },
) 