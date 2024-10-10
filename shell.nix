with import <nixpkgs> {};

mkShell {

  name = "mtkclient";
  
  buildInputs = with python3Packages; [
		capstone
		colorama
		flake8
		fusepy
		keystone
		keystone-engine
		mock
		pycryptodome
		pycryptodomex
		pyserial
		pyside6
		pyusb
		setuptools
		shiboken6
		unicorn
		wheel

  # workaround : use qttools in place of pyside6 script
  # since they are missing https://github.com/NixOS/nixpkgs/issues/277849
    qt5.qttools
	];

}
