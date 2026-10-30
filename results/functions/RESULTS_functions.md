# Function-start recovery (development images)

Command: `python eval/eval_functions.py --dataset C:\Users\singh\projects\cbomscan\dataset\out_esp32`. Truth: STT_FUNC symbols (size > 0) of the unstripped ELF inside the image's code segments. Signed (`__sbv2_`) copies are excluded (same code).

| level | images | true starts | recovered | correct | precision | recall |
|---|---|---|---|---|---|---|
| all | 165 | 41589 | 41051 | 41051 | 1.000 | 0.987 |
| O0 | 33 | 10318 | 10285 | 10285 | 1.000 | 0.997 |
| O1 | 33 | 8019 | 7856 | 7856 | 1.000 | 0.980 |
| O2 | 33 | 7594 | 7467 | 7467 | 1.000 | 0.983 |
| O3 | 33 | 7411 | 7269 | 7269 | 1.000 | 0.981 |
| Os | 33 | 8247 | 8174 | 8174 | 1.000 | 0.991 |
