__author__ = 'dank'

import setuptools

COSMO_CELERY_VERSION = "0.1.1"
COSMO_CELERY_BRANCH = "develop"
COSMO_CELERY = "https://github.com/CloudifySource/cosmo-celery-common/tarball/{0}".format(COSMO_CELERY_BRANCH)

setuptools.setup(
    zip_safe=False,
    name='cosmo-plugin-chef-client-common',
    version='0.1.0',
    author='yoni',
    author_email='yoni@fewbytes.com',
    packages=['chef_client_common'],
    license='LICENSE',
    description='Common code for chef related cosmo plugins',
    install_requires=[
        "celery",
        "cosmo-celery-common",
        "requests",
    ],
    dependency_links=["{0}#egg=cosmo-celery-common-{1}".format(COSMO_CELERY, COSMO_CELERY_VERSION)]
)
