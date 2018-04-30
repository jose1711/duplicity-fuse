'''
Created on 30.04.2018
@author: konsumverweigerer
'''
import setuptools
setuptools.setup(
    name = "DuplicityFuse",
    packages = setuptools.find_packages(),
    include_package_data = True,
    install_requires = ['fuse-python'],
    version = "0.1.0",
    description = "Filesystem interface to duplicity backups",
    author = "Peter Gruber",
    author_email = "konsumverweigerer@web.de",
    url = "https://github.com/konsumverweigerer/duplicity-fuse",
    download_url = "https://github.com/konsumverweigerer/duplicity-fuse/archive/master.zip",
    entry_points={
        'console_scripts': [
            'duplicity_fuse = duplicityfuse.main:main',
        ],
    },
    keywords = ["encoding", "i18n", "xml"],
    classifiers = [
        "Programming Language :: Python :: 2.6",
        "Intended Audience :: Developers",
        "Intended Audience :: End Users/Desktop",
        "License :: Other/Proprietary License",
        "Operating System :: Linux",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Archiving :: Backup",
        "Topic :: System :: Filesystems",
        ],
    long_description = """\
DuplicityFuse lets you mount abckup archives from duplicity as directories.
"""
)
