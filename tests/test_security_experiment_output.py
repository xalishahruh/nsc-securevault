from pathlib import Path

import pytest

from experiments.security_experiments import HEADER, write_csv


def test_security_experiment_csv_refuses_to_overwrite_existing_evidence(tmp_path: Path):
    output = tmp_path / "security_outcomes.csv"
    output.write_text("preserved evidence\n", encoding="utf-8")
    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        write_csv([], output)
    assert output.read_text(encoding="utf-8") == "preserved evidence\n"
    assert list(tmp_path.iterdir()) == [output]


def test_security_experiment_csv_publishes_new_output_without_temp_files(tmp_path: Path):
    output = tmp_path / "new" / "security_outcomes.csv"
    write_csv([], output)
    assert output.read_text(encoding="utf-8").splitlines() == [",".join(HEADER)]
    assert list(output.parent.iterdir()) == [output]
