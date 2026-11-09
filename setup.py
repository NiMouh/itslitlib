from setuptools import setup
from setuptools.command.install import install


class InstallWithPthInSitePackages(install):
    """Install data files into site-packages so .pth is processed by Python."""

    def finalize_options(self):
        super().finalize_options()
        self.install_data = self.install_lib


setup(
    data_files=[("", ["itslitlib_startup.pth"])],
    cmdclass={"install": InstallWithPthInSitePackages},
)
