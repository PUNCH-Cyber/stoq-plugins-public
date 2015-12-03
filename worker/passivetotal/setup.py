from setuptools import setup, find_packages

setup(
    name="passivetotal",
    version="0.5.1",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Query PassiveTotal API for a domain or IP address",
    packages=find_packages(),
    package_data={'passivetotal': ['passivetotal.stoq', 'templates/*.tpl']},
    include_package_data=True,
)
