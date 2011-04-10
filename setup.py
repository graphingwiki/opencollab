# -*- coding: utf-8 -*-
from distutils.core import setup

setup(name='opencollab', version='$Rev$',
      author='Joachim Viide, Pekka Pietikäinen, Mika Seppänen, Lari Huttunen, Juhani Eronen',
      author_email='contact@clarifiednetworks.com',
      description='OpenCollab XML-RPC SDK',
      packages=['opencollab'],
      package_data={'opencollab': ['*/*.py']},
      scripts=[ 'scripts/opencollab-attachfile',
        'scripts/opencollab-bluetooth-services',
        'scripts/opencollab-iwlist-scan',
        'scripts/opencollab-clone-pages',
        'scripts/opencollab-codetools-uploader',
        'scripts/opencollab-burpsuite-uploader',
        'scripts/opencollab-create-gallery',
        'scripts/opencollab-csv-meta',
        'scripts/opencollab-defensics-downloader',
        'scripts/opencollab-defensics-uploader',
        'scripts/opencollab-delete-pages',
        'scripts/opencollab-downloader',
        'scripts/opencollab-import-nvd-xml',
        'scripts/opencollab-instantiate-objects',
        'scripts/opencollab-mtr',
        'scripts/opencollab-multi-resolver',
        'scripts/opencollab-notifier',
        'scripts/opencollab-nmap-uploader',
        'scripts/opencollab-puppet-uploader',
        'scripts/opencollab-nmap-targets',
        'scripts/opencollab-nessus-uploader',
        'scripts/opencollab-ettercap-uploader',
        'scripts/opencollab-push-tickets',
        'scripts/opencollab-remove-dups',
        'scripts/opencollab-spam-reader',
        'scripts/opencollab-upload-identities',
        'scripts/opencollab-uploader'])
