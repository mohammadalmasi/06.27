# How the ML SQL Injection Scanner Works (Step by Step)

This document traces **one example** through the scanner so you can see exactly what happens.

---

## Example source code

```python
def vulnerable_sql_high_1():
    """Direct string concatenation in SELECT"""
    user_id = request.form["user_id"]
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(query)
```

---

## Step 1: Tokenize

The scanner turns the whole file into a list of tokens (words/symbols). For this code it is roughly:

| Token index | Token                | Line |
|-------------|----------------------|------|
| 0           | `def`                | 1    |
| 1           | `vulnerable_sql_high_1` | 1  |
| 2           | `(`                  | 1    |
| 3           | `)`                  | 1    |
| 4           | `:`                  | 1    |
| 5           | `user_id`            | 2    |
| 6           | `=`                  | 2    |
| 7           | `request`            | 3    |
| 8           | `.`                  | 3    |
| 9           | `form`               | 3    |
| 10          | `[`                  | 3    |
| 11          | `"user_id"`          | 3    |
| 12          | `]`                  | 3    |
| 13          | `query`              | 4    |
| 14          | `=`                  | 4    |
| 15          | `"SELECT`           | 4    |
| 16          | `*`                  | 4    |
| 17          | `FROM`               | 4    |
| 18          | `users`              | 4    |
| 19          | `WHERE`              | 4    |
| 20          | `id`                 | 4    |
| 21          | `=`                  | 4    |
| 22          | `'`                  | 4    |
| 23          | `"`                  | 4    |
| 24          | `+`                  | 4    |
| 25          | `user_id`            | 4    |
| 26          | `+`                  | 4    |
| 27          | `"`                  | 4    |
| 28          | `'`                  | 4    |
| 29          | `cursor`             | 5    |
| 30          | `.`                  | 5    |
| 31          | `execute`            | 5    |
| 32          | `(`                  | 5    |
| 33          | `query`              | 5    |
| 34          | `)`                  | 5    |

So you get one long list of tokens (exact split may vary slightly).

---

## Step 2: Sliding windows

- The model was trained on **windows** of 200 tokens (`WINDOW_LENGTH = 200`).
- Your file has only ~35 tokens, so there is **one window**: tokens from index 0 to the end.
- That one window is **padded with zeros** up to length 200 (so the model always sees 200 “positions”).

So in this example: **one window**, so the model is called **once**.

---

## Step 3: Tokens → vectors → X

- Each token (e.g. `"query"`, `"SELECT"`, `"+"`, `user_id`, …) is turned into a vector of length 300 (using Word2Vec, or zeros if the token is unknown).
- Those vectors are stacked into a matrix: **35 rows × 300 columns** (one row per token).
- Then it is **padded** to **200 rows × 300 columns** (extra rows = zeros).
- That is wrapped in a batch dimension:

**X** = shape **(1, 200, 300)**

Meaning: 1 sample, 200 time steps, 300 features per step. Your real code is in the first ~35 steps; the rest is padding.

---

## Step 4: Model output

```python
pred = self._model.predict(X, verbose=0)
prob = float(pred.ravel()[0])
```

- The model receives that one **X**.
- It outputs **one number**, e.g. **prob = 0.97** (high = “this looks like SQL injection”).

So for this exact code: **one number** between 0 and 1.

---

## Step 5: Threshold and reported line

- Default threshold is **0.5**.
- If **prob ≥ 0.5** (e.g. 0.97), the scanner says: “vulnerability”.
- It needs a **line number**. The window started at token index **0**, which is on **line 1**. The code maps the window’s token range to a line; for this single window it will typically report one of the lines where the dangerous pattern is (often line 4 or 5 in this snippet).
- It creates **one** result, e.g.:

  - **Line:** 4 (or 5, depending on how `token_index_to_line_number` maps it)
  - **Description:** `"ML BiLSTM: potential SQL injection (confidence: 0.97)"`
  - **Severity:** `"high"`
  - **Confidence:** 0.97

So for this exact code you usually get **one vulnerability** reported on the line with `query = "SELECT ..."` or `cursor.execute(query)`.

---

## Step 6: Deduplicate

- Here you only had one window and one report, so deduplication does nothing.
- **Final result:** a list with **one** `SQLInjectionVulnerability` for this file.

---

## Short summary for this exact code

| Step | What happens with this code |
|------|------------------------------|
| 1    | File → ~35 tokens. |
| 2    | 1 window (code is shorter than 200 tokens). |
| 3    | Those tokens → 35×300 vectors, then padded to 200×300 → **X** shape (1, 200, 300). |
| 4    | Model predicts **one** number, e.g. **0.97**. |
| 5    | 0.97 ≥ 0.5 → report vulnerability at one line (e.g. line 4 or 5). |
| 6    | One vulnerability in the result list. |

**In one sentence:** Your exact code → one token sequence → one **X** → one **prob** → one reported vulnerability (with a line number and confidence).

second example

# How the ML SQL Injection Scanner Works (Step by Step)

---

## Example source code

```python
def vulnerable_sql_high_1():
    """Direct string concatenation in SELECT"""
    user_id = request.form["user_id"]
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(query)

def vulnerable_sql_high_2():
    """F-string with SQL"""
    name = request.args.get("name")
    query = f"SELECT * FROM users WHERE name = '{name}'"
    cursor.execute(query)
```

---

## Step 1: Tokenize

The scanner turns the whole file into a flat list of tokens (words/symbols):

```
["def", "vulnerable_sql_high_1", "(", ")", ":", "user_id", "=",
 "request", ".", "form", "[", "\"user_id\"", "]",
 "query", "=", "\"SELECT", "*", "FROM", "users", "WHERE", "id", "=",
 "'", "\"", "+", "user_id", "+", "\"", "'",
 "cursor", ".", "execute", "(", "query", ")",
 "def", "vulnerable_sql_high_2", ...
 "name", "=", "request", ".", "args", ".", "get", "(", "\"name\"", ")",
 "query", "=", "f\"SELECT", ...,
 "cursor", ".", "execute", "(", "query", ")", ...]
```

For this file (~46 lines) you get roughly **200+ tokens** total.

---

## Step 2: Sliding windows

The scanner does NOT feed all tokens to the model at once.
It uses a **sliding window** to scan through the token list:

```
WINDOW_LENGTH = 200   (how many tokens per window)
WINDOW_STEP   =   5   (how many tokens to move forward each time)
```

So the loop is:

```
Window 1:  tokens[0  : 200]  → starts at line ~1
Window 2:  tokens[5  : 205]  → starts at line ~3
Window 3:  tokens[10 : 210]  → starts at line ~5
Window 4:  tokens[15 : 215]  → starts at line ~7
Window 5:  tokens[20 : 220]  → starts at line ~11
Window 6:  tokens[25 : 225]  → starts at line ~13
Window 7:  tokens[30 : 230]  → starts at line ~14
...
```

Each window **overlaps** the previous one. The model is called **once per window**.

---

## Step 3: Tokens → vectors → X

For each window:

1. Each token is looked up in **Word2Vec** → converted to a vector of 300 numbers.
   - e.g. `"query"` → `[0.12, -0.45, 0.87, ...]` (300 numbers)
   - unknown tokens → `[0, 0, 0, ...]` (300 zeros)

2. Those vectors are stacked into a matrix:
   - shape: `[window_length, 300]`  →  e.g. `[200, 300]`

3. Pad/truncate to exactly `window_length=200` rows.

4. Wrap in a batch:  **X** = shape `(1, 200, 300)`
   - 1 sample, 200 time steps, 300 features per step.

---

## Step 4: Model predicts one prob per window

```python
pred = self._model.predict(X, verbose=0)
prob = float(pred.ravel()[0])   # one number between 0 and 1
```

- **prob = 0.97** → "very likely this window contains SQL injection"
- **prob = 0.10** → "very unlikely"

---

## Step 5: Threshold check and reported line

```python
if prob >= self.confidence_threshold:   # default 0.5
    line_number = token_index_to_line_number(code, start)
    # report vulnerability at that line
```

- If `prob >= 0.5`  →  report a vulnerability.
- The **line number** is the line where the **first token** of that window lives.
- This is NOT the model saying "line X is the exact bug". It says:
  "the window that **starts at** this line is suspicious."

---

## Step 6: Why multiple lines are reported

Because the window slides **5 tokens at a time**, consecutive windows start at
different lines. If several windows overlap the SQL code, all of them can get
`prob >= 0.5`, and each one reports its own start line:

| Window | Start token | Start line | prob  | Reported? |
|--------|-------------|-----------|-------|-----------|
| ...    | ...         | line 11   | 0.82  | yes       |
| ...    | ...         | line 13   | 0.97  | **yes → line 13** |
| ...    | ...         | line 14   | 0.97  | **yes → line 14** |
| ...    | ...         | line 15   | 0.969 | **yes → line 15** |
| ...    | ...         | line 17   | 0.968 | **yes → line 17** |
| ...    | ...         | line 19   | 0.935 | **yes → line 19** |
| ...    | ...         | line 35   | 0.20  | no (< 0.5)|

So the **model does not know which specific line is the bug**. It gives one score
for a whole 200-token block. The line number is just "where that block starts."

---

## Step 7: Deduplicate

After all windows, if the same line number appears more than once (because two
windows both started on the same line), the scanner keeps **only the one with
the highest confidence**:

```python
def _deduplicate_by_line(self, vuln_list):
    by_line = {}
    for v in vuln_list:
        if v.line_number not in by_line or v.confidence > by_line[v.line_number].confidence:
            by_line[v.line_number] = v
    return list(by_line.values())
```

---

## Final result

```
Total vulnerabilities: 5
[line 13] high confidence=0.97 : ML BiLSTM: potential SQL injection
[line 14] high confidence=0.97 : ML BiLSTM: potential SQL injection
[line 15] high confidence=0.969: ML BiLSTM: potential SQL injection
[line 17] high confidence=0.968: ML BiLSTM: potential SQL injection
[line 19] high confidence=0.935: ML BiLSTM: potential SQL injection
```

---

## One-sentence summary

> The file is tokenized, a **window of 200 tokens slides 5 tokens at a time**,
> each window is fed to the BiLSTM model and gets **one prob**,
> every window with `prob >= 0.5` reports the **start line** of that window as vulnerable.



The file HOW_ML_SCANNER_WORKS.md is updated with the corrected full explanation including:
Step 1 — Tokenize the file into a flat list of tokens.
Step 2 — Sliding window: WINDOW_LENGTH=200, WINDOW_STEP=5 (this is the key).
Step 3 — Tokens → Word2Vec vectors → X shape (1, 200, 300).
Step 4 — Model gives one prob per window.
Step 5 — If prob >= 0.5, report the start line of that window.
Step 6 — Why multiple lines appear: each window starts 5 tokens later = different line.
Step 7 — Deduplicate (keep highest confidence per line).


Let me draw it visually with your actual tokens.

Imagine your tokens are numbered. Each token lives on a line:
token 0  → line 5   → "def"
token 1  → line 5   → "vulnerable_sql_high_1"
token 2  → line 5   → "("
token 3  → line 5   → ")"
token 4  → line 5   → ":"
token 5  → line 7   → "user_id"
token 6  → line 7   → "="
token 7  → line 7   → "request"
token 8  → line 7   → "."
token 9  → line 7   → "form"
token 10 → line 11  → "def"
token 11 → line 11  → "vulnerable_sql_high_2"
token 12 → line 11  → "("
token 13 → line 13  → "name"       ← SQL code starts here
token 14 → line 14  → "query"
token 15 → line 15  → "cursor"
...

Now the sliding window (step=5) creates these windows:
Window 1:  starts at token 0  (line 5)   → model gets tokens 0..199
Window 2:  starts at token 5  (line 7)   → model gets tokens 5..204
Window 3:  starts at token 10 (line 11)  → model gets tokens 10..209
Window 4:  starts at token 13 (line 13)  → model gets tokens 13..212  ← SQL code
Window 5:  starts at token 14 (line 14)  → model gets tokens 14..213  ← SQL code
Window 6:  starts at token 15 (line 15)  → model gets tokens 15..214  ← SQL code

Windows 4, 5, 6 all contain the SQL injection code (because the window is 200 tokens wide and they all overlap). So the model gives all of them a high prob:
Window 4 → prob 0.97 → report line 13 ✓
Window 5 → prob 0.97 → report line 14 ✓
Window 6 → prob 0.97 → report line 15 ✓

The key point
All three windows contain the same SQL injection code because they overlap. The only difference between them is where they start. Window 4 starts at line 13, window 5 starts at line 14, window 6 starts at line 15.
So you get 3 reports for 3 different lines — not because the model found 3 separate bugs, but because 3 overlapping windows all saw the same bug and each one reported its own start line.