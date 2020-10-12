all: python 

.PHONY: python
python: *.pxd *.pyx *.py
	python setup.py build_ext -i
	python -m unittest discover

clean:
	rm -rf m17.bin  build/  *.so
