from setuptools import setup, find_packages

setup(
    name="smtp",
    version="2.0.0",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public/v2",
    license="Apache License 2.0",
    description="SMTP Parser Worker",
    packages=find_packages(),
    include_package_data=True,
    install_requires=['pyzmail36>=1.0.3', 'beautifulsoup4>=4.6.3'],
    package_data={'smtp': ['*.stoq']},
)
