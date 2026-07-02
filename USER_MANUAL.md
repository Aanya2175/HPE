# Anomaly Detector — User Manual

A command-line tool that runs streaming anomaly-detection algorithms over a CSV of network traffic and reports how well each algorithm separated normal rows from attacks.

---

## 1. What it does

You give it a CSV file. Each row is one record (a network flow or a
time-series event) with some numeric measurements and a column saying whether
that row was truly normal or an attack. The tool reads the file row by row,
shows the measurements to the algorithm, the algorithm guesses "normal" or
"anomaly", and the tool compares each guess to the truth and prints a scorecard
(precision, recall, F1, and more).

---

## 2. Quick start

Put your CSV in the same folder as the program, then:

```
make                                         # build the program (run once, and after any code change)
./anomaly_detector -m flow -a all data.csv   # run all algorithms on data.csv
```

- `make` turns the source files into the program called `anomaly_detector`.
- `./anomaly_detector ...` runs it. The `./` means "the program in this folder".
- If you change any code, run `make` again before running, or you'll be testing the old version.

Shortest possible run (uses every default):

```
./anomaly_detector data.csv
```

---

## 3. The flags

A "flag" is an option starting with a dash that you type after the program
name. The CSV filename is **not** a flag — it has no dash and goes last.

| Flag | Takes a value? | What it does | Default |
|------|----------------|--------------|---------|
| `-a NAME` | yes | Which algorithm to run: `cusum`, `adwin`, or `all` | `all` |
| `-m MODE` | yes | `flow` or `ts` — selects the default profile of columns and parameters | `flow` |
| `-f LIST` | yes | Comma-separated feature column names (quote them) | mode's built-in list |
| `-l NAME` | yes | The label (truth) column name | `Label` (flow) / `label` (ts) |
| `-p PARAMS` | yes | Tuning knobs as `key=value,key=value` | each algorithm's macro defaults |
| `-r` | no | Use raw features (turn off normalization) | normalization on |
| `-j` | no | Also print machine-readable JSON | off |
| `-h` | no | Show help and exit | — |

Flags that **take a value** (`-a -m -f -l -p`) are followed by their value.
Flags that are **switches** (`-r -j -h`) stand alone.

Order of flags doesn't matter. Any flag you leave out simply uses its default.

---

## 4. Modes

`-m` selects which set of defaults to start from:

- `-m flow` — flow data (CICIDS-style). Default feature names like `Flow
  Bytes/s`; default label column `Label`.
- `-m ts` — time-series data (Zeek-style). Default feature names like
  `orig_bytes`; default label column `label`.

The **detection logic is identical** in both modes — only the default
column names and default parameter values differ. If you supply `-f`, `-l`, and
`-p` yourself, the mode mostly just affects which parameter defaults apply.

If you don't pass `-m`, it defaults to `flow`.

---

## 6. Column names must match your CSV exactly

The tool finds columns by their name in the CSV header, and the match is
**case-sensitive**. `Label` and `label` are different. `Flow Bytes/s` will not
match `Flow Bytes /s`. The safe habit is to copy names straight from the first
line of your CSV.

If your CSV already uses the built-in default names for the mode, you can skip
`-f` and `-l` entirely. If it uses different names, you must pass them.

Because feature names usually contain spaces and slashes, **quote** the `-f`
list:

```
-f "Flow Bytes/s,Flow Packets/s,Flow IAT Mean"
```

---

## 7. Algorithm parameters

Override with `-p key=value,key=value` (no spaces). Unknown keys and invalid
values (e.g. `threshold=abc`) are ignored and the default is used instead — it
won't crash.

## 8. Examples

Run everything with defaults on flow data:
```
./anomaly_detector -m flow -a all data.csv
```

Run only CUSUM, on time-series data:
```
./anomaly_detector -m ts -a cusum data_ts.csv
```

Custom feature columns and a custom label column:
```
./anomaly_detector -a cusum -f "Flow Bytes/s,Flow Packets/s" -l Attack data.csv
```

Override CUSUM's tuning, and also print JSON:
```
./anomaly_detector -a cusum -p threshold=4.0,drift=0.06 -j data.csv
```

Feed raw (un-normalized) features:
```
./anomaly_detector -a adwin -r data.csv
```

---

## 9. Reading the output

For each algorithm, the report is grouped into sections:

- **Dataset** — rows processed and how many distinct anomaly events were in the file.
- **Confusion matrix (raw)** — the four building-block counts:
  - **TP** caught a real attack, **FP** false alarm, **FN** missed an attack, **TN** correctly stayed quiet.
- **Detection quality (derived)** — computed from the four counts:
  - **Precision** = of the rows it flagged, how many were real attacks.
  - **Recall** = of the real attacks, how many it caught.
  - **F1** = balance of precision and recall.
  - **Specificity / FPR** = how well it stays quiet on normal traffic.
  - **Balanced accuracy / MCC** = quality measures that stay honest even when
    attacks are rare (use these over plain accuracy on imbalanced data).
- **Responsiveness** — how many anomaly events it caught and the average number
  of rows it took to notice one.
- **Cost** — model memory, time per row, and throughput.

With `-j`, one JSON object per algorithm is also printed so a script can read
the results for plots or comparison tables.

---



