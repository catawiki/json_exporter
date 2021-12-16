'''
Setup script for json_exporter
'''
from setuptools import setup, find_packages
from json_exporter import __version__

setup(
    name="json_exporter",
    version=__version__,
    description="export metrics from JSON HTTP(S) API endpoints",
    url="https://catawiki.com",
    author="Ids van der Molen",
    author_email="i.van.der.molen@catawiki.nl",
    license="MIT",
    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 5 - Production/Stable',

        # Indicate who your project is intended for
        'Intended Audience :: Developers',
        # pick a classifier from https://pypi.python.org/pypi?%3Aaction=list_classifiers
        'Topic :: Utilities',

        # Pick your license as you wish (should match "license" above)
        # or choose from https://choosealicense.com
        'License :: OSI Approved :: MIT License',

        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
    ],
    keywords="prometheus json exporter",
    packages=find_packages(),
    install_requires=["jsonpath-ng==1.5.3",
                      "prometheus-client==0.12.0",
                      "PyYAML==6.0",
                      "requests==2.26.0"],
    python_requires=">=3.6",
    py_modules=[],
    entry_points={
        'console_scripts': [
            'json_exporter = json_exporter.main:main'
        ]
    }

)
