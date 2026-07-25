from setuptools import setup


# The Python distribution is deliberately universal. Platform-native fast
# paths ship in the separately matrix-built ``one_link_native`` wheels, while
# standalone applications stage a freshly compiled CDC sidecar during their
# own build. Keeping those binaries out of this wheel makes the single
# ``py3-none-any`` artifact honest and installable on every supported OS.
setup()
