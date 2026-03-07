# How the ML Command Injection Scanner Works (Step by Step)

This document traces **one example** through the scanner so you can see exactly what happens.

---

## Example source code

```python
def vulnerable_cmd_high_1():
    """os.system with user input"""
    user_cmd = request.args.get("cmd")
    os.system(user_cmd)
```

---

## Step 1: Tokenize

The scanner turns the whole file into a list of tokens (words/symbols). For this code it is roughly:

| Token index | Token                | Line |
|-------------|----------------------|------|
| 0           | `def`                | 1    |
| 1           | `vulnerable_cmd_high_1` | 1  |
| 2           | `(`                  | 1    |
| 3           | `)`                  | 1    |
| 4           | `:`                  | 1    |
| 5           | `user_cmd`           | 3    |
| 6           | `=`                  | 3    |
| 7           | `request`            | 3    |
| 8           | `.`                  | 3    |
| 9           | `args`               | 3    |
| ...         | ...                  | ...  |
| (later)     | `os`                 | 5    |
| (later)     | `.`                  | 5    |
| (later)     | `system`             | 5    |
| (later)     | `(`                  | 5    |
| (later)     | `user_cmd`           | 5    |
| (later)     | `)`                  | 5    |

So you get one long list of tokens (exact split may vary slightly). Tokenization matches the training pipeline (same as `myutils.getTokens` in the reference repo).

---

## Step 2: Sliding windows

- The model was trained on **windows** of 200 tokens (`WINDOW_LENGTH = 200`).
- The window **steps by 5 tokens** each time (`WINDOW_STEP = 5`).
- Your file might have ~30 tokens, so there is **one window** (tokens 0 to end). That window is **padded with zeros** up to length 200.

So in this small example: **one window**, and the model is called **once**. For longer files you get many overlapping windows (e.g. window 1: tokens 0–199, window 2: tokens 5–204, …).

---

## Step 3: Tokens → vectors → X

- Each token is turned into a vector of length 300 using **Word2Vec** (or zeros if the token is unknown).
- Those vectors are stacked, then **padded** to 200 rows × 300 columns.
- That is wrapped in a batch dimension:

**X** = shape **(1, 200, 300)**

Meaning: 1 sample, 200 time steps, 300 features per step.

---

## Step 4: Model output (logits → probability)

```python
pred = self._model.predict(X, verbose=0)
raw = float(pred.ravel()[0])
# Model outputs logits (no sigmoid in saved graph). Convert to probability.
prob = float(1.0 / (1.0 + np.exp(-np.clip(raw, -709.0, 709.0))))
```

- The saved command-injection BiLSTM has a final layer **without** sigmoid, so it outputs a **raw score (logit)**.
- The scanner applies **sigmoid** so that **prob** is in **[0, 1]** (like the XSS scanner).
- High **prob** (e.g. 0.7) = “this window looks like command injection”. Low (e.g. 0.3) = “unlikely”.

So for each window you get **one number** between 0 and 1.

---

## Step 5: Threshold and which lines to report

- Default threshold is **0.5**.
- If **prob ≥ 0.5**, the scanner does **not** just report the line where the window **starts**. Instead it looks at **all lines in that window** and reports only lines that look command-injection-relevant.

**Relevance scoring (`_command_injection_relevance`):**

- A line gets a score ≥ 1 if it contains command/code-execution patterns, for example:
  - **Strong (score 2–3):** `os.system`, `os.popen`, `subprocess.*` with `shell=True`, `eval(`, `exec(`, `__import__`.
  - **Weaker:** `subprocess.` on the line adds score.
  - **request. / request[** only count when the **same line** also has a command sink (so SQL/XSS-only lines like `user_id = request.form["user_id"]` are not reported as command injection).
  - **Context:** `user_`, `filename`, `command`, `cmd`, `dir`, `code` add score when the line already has a sink.
- Docstrings and comments (`"""..."""`, `'''...'''`, `#`) get score **0** so they are not reported.
- If **no** line in the window has relevance ≥ 1, **nothing** is reported for that window (no fallback to the window-start line).

So for the example code:

- The window contains line 5: `os.system(user_cmd)`. That line has `os.system` → relevance ≥ 1.
- Line 3: `user_cmd = request.args.get("cmd")` has `request.` but no command sink on the same line; it may get 0 or low score unless the relevance logic also gives points for context. The line with the sink (line 5) is the one reported.
- The scanner reports **line 5** (and any other line in the window with relevance ≥ 1), not necessarily the window’s start line.

One vulnerability is created, e.g.:

- **Line:** 5  
- **Description:** `"ML BiLSTM: potential command injection (confidence: 0.xx)"`  
- **Severity:** `"high"`  
- **Confidence:** prob (rounded)

---

## Step 6: Deduplicate by line

- Several overlapping windows can all have **prob ≥ 0.5** and can all suggest the **same line** (e.g. line 9).
- The scanner keeps **one result per line**: the one with the **highest confidence** for that line.

So the final list has **at most one** `CommandInjectionVulnerability` per source line.

---

## Short summary for this exact code

| Step | What happens with this code |
|------|-----------------------------|
| 1    | File → list of tokens. |
| 2    | 1 window (or more for longer files), step 5. |
| 3    | Tokens → Word2Vec vectors, padded to 200×300 → **X** shape (1, 200, 300). |
| 4    | Model outputs **raw**; we apply **sigmoid** → **prob** in [0, 1]. |
| 5    | If prob ≥ 0.5, find all lines in the window with command-injection relevance ≥ 1; report those (e.g. line 5). |
| 6    | Deduplicate by line (keep highest confidence per line). |

**In one sentence:** The file is tokenized, **windows of 200 tokens slide 5 at a time**, each window gets **one prob** (after sigmoid); for every window with prob ≥ 0.5 we report **only lines inside that window that look command-injection-relevant**, then deduplicate by line.

---

# Second example: longer file, multiple windows

---

## Example source code

```python
def vulnerable_cmd_high_1():
    """os.system with user input"""
    user_cmd = request.args.get("cmd")
    os.system(user_cmd)

def vulnerable_cmd_high_2():
    """subprocess with shell=True"""
    filename = request.form.get("filename")
    subprocess.run(f"cat {filename}", shell=True)
```

---

## Step 1: Tokenize

The scanner turns the whole file into a flat list of tokens:

```
["def", "vulnerable_cmd_high_1", "(", ")", ":", "user_cmd", "=",
 "request", ".", "args", ".", "get", "(", "\"cmd\"", ")",
 "os", ".", "system", "(", "user_cmd", ")",
 "def", "vulnerable_cmd_high_2", ...,
 "filename", "=", "request", ".", "form", ".", "get", ...,
 "subprocess", ".", "run", "(", "f\"cat", "{filename}", "\"", ",", "shell", "=", "True", ")", ...]
```

For a file like this you get **80+ tokens** total.

---

## Step 2: Sliding windows

Same as XSS/SQL scanner:

```
WINDOW_LENGTH = 200
WINDOW_STEP   =   5
```

- Window 1: tokens[0   : 200]  → starts at line ~1  
- Window 2: tokens[5   : 205]  → starts at line ~3  
- Window 3: tokens[10  : 210]  → …  
- …

Each window **overlaps** the previous one. The model is called **once per window**.

---

## Step 3: Tokens → vectors → X

For each window:

1. Each token → Word2Vec vector (300 numbers), or zeros if unknown.
2. Stack into a matrix of shape `[200, 300]`, then wrap in a batch.
3. **X** = shape `(1, 200, 300)`.

---

## Step 4: Model output and sigmoid

```python
raw = float(pred.ravel()[0])
prob = 1.0 / (1.0 + exp(-clip(raw, -709, 709)))
```

- **prob** is in [0, 1]. High value ⇒ “this window looks like command injection”.

---

## Step 5: Which lines get reported (relevance, not just window start)

When **prob ≥ 0.5**, the scanner does **not** report only the line where the window **starts**. It:

1. Computes the **line range** of the window: from the line of the first token in the window to the line of the last token.
2. Calls **`_relevant_lines_in_range(lines, line_start, line_end)`**: it returns every line in that range whose **command-injection relevance** is ≥ 1.
3. For each of those lines it adds (or updates) a vulnerability in **by_line**, keeping the **highest confidence** if the same line is hit by several windows.

So you might get:

| Window | Start line | prob  | Lines in window with relevance ≥ 1 | Reported lines |
|--------|------------|-------|--------------------------------------|-----------------|
| 1      | 1          | 0.52  | 5, 11                                | 5, 11           |
| 2      | 3          | 0.51  | 5, 11                                 | (update 5, 11 if higher conf) |
| …      | …          | …     | …                                    | …               |

- Line 5: `os.system(user_cmd)` — `os.system` → strong relevance.
- Line 11: `subprocess.run(f"cat {filename}", shell=True)` — `subprocess.` + `shell=True` → strong relevance.

So the **reported line numbers** are the ones that **look like command injection** inside the window, not every line the window touches.

---

## Step 6: Deduplicate by line

- Many windows can suggest the **same** line (e.g. line 5).
- For each line we keep **one** result: the one with the **highest confidence**.

```python
if line_number not in by_line or round(prob, 3) > by_line[line_number].confidence:
    by_line[line_number] = CommandInjectionVulnerability(...)
```

Final list: **at most one** vulnerability per line, sorted by line number.

---

## Why we use relevance (and sigmoid)

1. **Sigmoid:** The saved command-injection model has **no sigmoid** on the last layer, so it outputs **logits**. Applying sigmoid in the scanner gives a proper probability in [0, 1] and a clear 0.5 threshold.
2. **Relevance:** The model scores a **whole 200-token window**. It does not tell us “line 9 is the bug.” By reporting only lines **inside** the window that have command-injection patterns (e.g. `os.system`, `os.popen`, `subprocess` with `shell=True`, `eval`, `exec`, `__import__`), we:
   - Reduce noise (e.g. avoid reporting blank or comment lines).
   - Avoid reporting SQL/XSS-only code as command injection (e.g. `request.form["user_id"]` without any command sink on the same line gets no relevance).
   - Point the user at the lines that actually look like command or code execution.

---

## Final result (example)

```
Total vulnerabilities: 2
[line 5]  high confidence=0.52: ML BiLSTM: potential command injection (confidence: 0.52)
[line 11] high confidence=0.52: ML BiLSTM: potential command injection (confidence: 0.52)
```

---

## One-sentence summary

> The file is tokenized, a **window of 200 tokens slides 5 tokens at a time**, each window is fed to the BiLSTM model and gets **one prob** (after sigmoid); every window with **prob ≥ 0.5** contributes reports only for **lines inside that window that have command-injection relevance ≥ 1**; then results are **deduplicated by line** (highest confidence kept).

---

## Summary of steps (full pipeline)

| Step | Description |
|------|-------------|
| 1 | Tokenize the file into a flat list of tokens (same style as training). |
| 2 | Sliding window: `WINDOW_LENGTH=200`, `WINDOW_STEP=5`. |
| 3 | Tokens → Word2Vec vectors → pad to 200 → **X** shape (1, 200, 300). |
| 4 | Model predicts one **raw** value per window; apply **sigmoid** → **prob** in [0, 1]. |
| 5 | If prob ≥ 0.5, collect all lines in the window with **command-injection relevance ≥ 1**; add/update them in **by_line** (keep highest confidence per line). |
| 6 | Output the list of vulnerabilities, one per line, sorted by line number. |
