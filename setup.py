from distribute_setup import use_setuptools
use_setuptools()

from setuptools import setup
version = "1.0-release"
setup(
    name = "atklite",
    version = version,
    install_requires = [
        "ssdeep",
        "python-magic",
    ],
    include_package_data = True,
    py_modules = ["atklite"],
    entry_points = {
        'console_scripts': [
            'atk-info = atklite:main',
        ],
    },

    author = "James Pleger",
    author_email = "jpleger@gmail.com",
    url = "https://bitbucket.org/jpleger/atk/",
    description = "Library to simplify process of gathering identifiable attributes about files",
    license = "ISC",
    long_description = open("README.txt").read(),
    classifiers = [
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: ISC License (ISCL)",
        "Operating System :: POSIX",
        "Programming Language :: Python :: 2 :: Only",
        "Topic :: Security",
    ],
)
