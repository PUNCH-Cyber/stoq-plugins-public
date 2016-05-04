from setuptools import setup, find_packages

setup(
    name="exif",
    version="0.9.2",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Processes a payload using ExifTool",
    packages=find_packages(),
    package_data={'exif': ['templates/*.tpl', 'exif.stoq']},
    include_package_data=True,
)
