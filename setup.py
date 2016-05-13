from setuptools import setup, find_packages

# We use requirements.txt instead of just declaring the requirements here
# because this helps with Docker package caching.
with open("requirements.txt") as requirements:
    install_requires = requirements.readlines()

# We use dev-requirements.txt instead of just declaring the requirements here
# because Read The Docs needs a requirements file.
with open("dev-requirements.txt") as dev_requirements:
    dev_requires = dev_requirements.readlines()

with open('README.md') as f:
    long_description = f.read()

setup(
    name="Qlutter TODOer",
    version="0.1",
    author="Adam Dangoor",
    description="Manage TODOs.",
    long_description=long_description,
    license='GNU Affero General Public License v3',
    packages=find_packages(),
    install_requires=install_requires,
    extras_require={
        "dev": dev_requires,
    },
    classifiers=[
        'Operating System :: POSIX',
        'Environment :: Web Environment',
        'License :: OSI Approved :: GNU Affero General Public License v3',
    ],
)
