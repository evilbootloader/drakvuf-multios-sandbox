"""extracted/ and dumps/ upload as one archive each (pack_dirs, 2026-11-13)."""
import zipfile

import pytest

from sandboxd.guests import TargetOs
from sandboxd.postprocessing.paths import (DUMPS_DIR, DUMPS_ZIP, EXTRACTED_DIR,
                                           EXTRACTED_ZIP)
from sandboxd.postprocessing.plugins import POSTPROCESS_PLUGINS, pack_dirs
from sandboxd.postprocessing.plugins.plugin_base import (PostprocessContext,
                                                         PostprocessingConfig)
from sandboxd.postprocessing.postprocess import check_plugin_requirements


def context(tmp_path):
    return PostprocessContext(analysis_dir=tmp_path, config=PostprocessingConfig(),
                              target_os=TargetOs.WINDOWS)


def test_both_directories_are_packed_after_cape_has_read_them():
    """cape_analysis reads extracted/ and dumps/ for `dropped` and
    `procmemory`; packing first would leave it nothing."""
    names = [p.function.__name__ for p in POSTPROCESS_PLUGINS]
    assert names.index("cape_analysis") < names.index("compress_extracted")
    assert names.index("cape_analysis") < names.index("compress_dumps")


def test_the_archive_carries_the_names_the_files_uploaded_under(tmp_path):
    """Sidecars included, and the directory goes once the zip is whole."""
    d = tmp_path / EXTRACTED_DIR
    d.mkdir()
    (d / "file.000001.mm").write_bytes(b"MZ" * 100)
    (d / "file.000001.metadata").write_text("{}")
    pack_dirs.compress_extracted(context(tmp_path))
    with zipfile.ZipFile(tmp_path / EXTRACTED_ZIP) as z:
        assert z.namelist() == ["extracted/file.000001.metadata",
                                "extracted/file.000001.mm"]
        assert z.read("extracted/file.000001.mm") == b"MZ" * 100
    assert not d.exists()


def test_an_empty_directory_makes_no_archive(tmp_path):
    """`_trace` creates both directories for every job; an empty zip in
    every manifest would say something was recovered."""
    (tmp_path / DUMPS_DIR).mkdir()
    pack_dirs.compress_dumps(context(tmp_path))
    assert not (tmp_path / DUMPS_ZIP).exists()
    assert (tmp_path / DUMPS_DIR).is_dir()


def test_what_does_not_fit_stays_in_the_directory(tmp_path):
    d = tmp_path / DUMPS_DIR
    d.mkdir()
    (d / "a.dmp").write_bytes(b"a" * 60)
    (d / "b.dmp").write_bytes(b"b" * 60)
    (d / "c.dmp").write_bytes(b"c" * 30)
    pack_dirs._pack(tmp_path, DUMPS_DIR, DUMPS_ZIP, 100)
    with zipfile.ZipFile(tmp_path / DUMPS_ZIP) as z:
        assert z.namelist() == ["dumps/a.dmp", "dumps/c.dmp"]
    assert [p.name for p in d.iterdir()] == ["b.dmp"]


def test_a_zip_that_failed_is_removed_and_the_files_kept(tmp_path, monkeypatch):
    """`_collect` skips the directory beside its archive, so a partial
    archive would hide the files it does not hold."""
    d = tmp_path / EXTRACTED_DIR
    d.mkdir()
    (d / "one").write_bytes(b"1")

    def broken(self, *a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(zipfile.ZipFile, "write", broken)
    with pytest.raises(OSError):
        pack_dirs.compress_extracted(context(tmp_path))
    assert not (tmp_path / EXTRACTED_ZIP).exists()
    assert (d / "one").exists()


def test_a_job_already_packed_is_left_alone(tmp_path):
    (tmp_path / EXTRACTED_DIR).mkdir()
    (tmp_path / EXTRACTED_ZIP).write_bytes(b"PK")
    plugin = next(p for p in POSTPROCESS_PLUGINS
                  if p.function is pack_dirs.compress_extracted)
    assert not check_plugin_requirements(tmp_path, plugin)
