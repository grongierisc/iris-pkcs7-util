# Licensed under the MIT License
# https://github.com/grongierisc/iris_pex_embedded_python/blob/main/LICENSE

import os

from setuptools import setup

def main():
    # Read the readme for use as the long description
    with open(os.path.join(os.path.abspath(os.path.dirname(__file__)),
                            'README.md'), encoding='utf-8') as readme_file:
        long_description = readme_file.read()

    # Do the setup
    setup(
        name='iris-gen-cms',
        description='iris-gen-cms',
        long_description=long_description,
        long_description_content_type='text/markdown',
        version='0.0.1',
        author='grongier',
        author_email='guillaume.rongier@intersystems.com',
        keywords='iris-gen-cms',
        url='https://github.com/grongierisc/iris-pkcs7-util',
        license='MIT',
        classifiers=[
            'Development Status :: 5 - Production/Stable',
            'Intended Audience :: Developers',
            'License :: OSI Approved :: MIT License',
            'Operating System :: OS Independent',
            'Programming Language :: Python :: 3.6',
            'Programming Language :: Python :: 3.7',
            'Programming Language :: Python :: 3.8',
            'Programming Language :: Python :: 3.9',
            'Programming Language :: Python :: 3.10',
            'Programming Language :: Python :: 3.11',
            'Topic :: Utilities'
        ],
        package_dir={'': 'src'},
        packages=['gencms'],
        python_requires='>=3.6',
        install_requires=[
            "asn1crypto==1.5.1",
            "pyOpenSSL==23.1.1"
        ],
        entry_points={
            'console_scripts': [
                'gencms = gencms.cli:main',
            ],
        }
    )


if __name__ == '__main__':
    main()
