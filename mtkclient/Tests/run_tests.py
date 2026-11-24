#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Test entry point for the mtkclient port test suite.
#
# Why not plain "python -m unittest": mtkclient/Library/utils.py rewraps
# sys.stdout/sys.stderr at import time (sys.stdout.detach()), which invalidates
# the stream references the default unittest runner captured earlier and crashes
# the summary output. Importing the package BEFORE creating the runner binds it
# to the (working) post-rewrap streams.
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

import mtkclient.Library.utils  # noqa: F401  (triggers the stdio rewrap up front)


def main():
    tests_dir = os.path.dirname(os.path.abspath(__file__))
    suite = unittest.defaultTestLoader.discover(start_dir=tests_dir, pattern="test_*.py")
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
