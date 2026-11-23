from pathlib import Path

import pytest

from experiments.security_experiments import (
    HEADER, gcm_exp_modify_header_aad, gcm_exp_truncate_container,
    cbc_exp_truncate_ciphertext, write_csv,
)


def test_experiments_distinguish_authentication_from_structural_rejection():
    aad = gcm_exp_modify_header_aad()
    assert aad.authentication_rejected and not aad.plaintext_returned
    for run in (gcm_exp_truncate_container, cbc_exp_truncate_ciphertext):
        outcome = run()
        assert outcome.exception_type == "MalformedContainerError"
        assert not outcome.authentication_rejected and not outcome.plaintext_returned


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
