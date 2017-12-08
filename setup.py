'''
Setup script for json_exporter
'''
from setuptools import setup, find_packages

setup(
    name="json_exporter",
    version="0.1.0",
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
        'Development Status :: 4 - Beta',

        # Indicate who your project is intended for
        'Intended Audience :: Developers',
        # pick a classifier from https://pypi.python.org/pypi?%3Aaction=list_classifiers
        'Topic :: Utilities',

        # Pick your license as you wish (should match "license" above)
        # or choose from https://choosealicense.com
        'License :: OSI Approved :: MIT License',

        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
    ],
    keywords="prometheus json exporter",
    packages=find_packages(),
    install_requires=["jsonpath-ng>=1.4.3",
                      "prometheus-client>=0.0.21",
                      "PyYAML>=3.12",
                      "requests>=2.18.4"],
    python_requires=">=2.7, <3",
    py_modules=[],
    entry_points={
        'console_scripts': [
            'json_exporter = json_exporter.main:main'
        ]
    }

)
