# -*- coding: utf-8 -*-
from distutils.core import setup

setup(name='opencollab', version='$Rev$',
      author='Joachim Viide, Pekka Pietikäinen, Mika Seppänen, Lari Huttunen, Juhani Eronen',
      author_email='contact@clarifiednetworks.com',
      description='OpenCollab XML-RPC SDK',
      packages=['opencollab'],
      package_data={'opencollab': ['*/*.py']},
      scripts=[ "scripts/opencollab-defensics-downloader",
"scripts/opencollab-puppet-uploader",
"scripts/opencollab-import-nvd-xml",
"scripts/opencollab-skipfish-uploader",
"scripts/opencollab-clone-pages",
"scripts/opencollab-nmap-uploader",
"scripts/opencollab-attachfile",
"scripts/opencollab-notifier",
"scripts/opencollab-upload-identities",
"scripts/opencollab-nmap-targets",
"scripts/opencollab-multi-resolver",
"scripts/opencollab-burpsuite-uploader",
"scripts/opencollab-bluetooth-services",
"scripts/opencollab-delete-pages",
"scripts/opencollab-create-gallery",
"scripts/opencollab-uploader",
"scripts/opencollab-remove-dups",
"scripts/opencollab-iwlist-scan",
"scripts/opencollab-defensics-uploader",
"scripts/opencollab-push-tickets",
"scripts/opencollab-nessus-uploader",
"scripts/opencollab-creategroups",
"scripts/opencollab-codetools-uploader",
"scripts/opencollab-host-agent",
"scripts/opencollab-csv-meta",
"scripts/opencollab-downloader",
"scripts/opencollab-ettercap-uploader",
"scripts/opencollab-instantiate-objects",
"scripts/opencollab-spam-reader",
"scripts/opencollab-import-package",
"scripts/opencollab-mtr" ])
