from setuptools import setup, find_packages

setup(name='quack',
      version='1.0.0',
      description='IDA plugin for duck typing functions by emulating them',
      url='https://github.com/harelon/quack',
      packages=find_packages(where="src"),
      package_dir={"": "src"},
      python_requires=">=3",
      zip_safe=True
      )
