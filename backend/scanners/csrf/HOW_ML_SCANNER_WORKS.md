# How the ML CSRF Scanner Works (Step by Step)

This document traces **one example** through the scanner so you can see exactly what happens.

---

## Example source code

```python
def vulnerable_csrf_high_1():
    """Flask route with POST method without CSRF protection"""
    from flask import Flask, request

    @app.route('/submit', methods=['POST'])
    def submit_form():
        data = request.form.get('data')
        return "OK"
```

---

## Step 1: Tokenize

The scanner turns the whole file into a list of tokens (words/symbols). For this code it is roughly:

| Token index | Token                | Line |
|-------------|----------------------|------|
| 0           | `def`                | 1    |
| 1           | `vulnerable_csrf_high_1` | 1  |
| 2           | `(`                  | 1    |
| 3           | `)`                  | 1    |
| 4           | `:`                  | 1    |
| ...         | ...                  | ...  |
| (later)     | `@app.route`         | 6    |
| (later)     | `methods`            | 6    |
| (later)     | `POST`               | 6    |
| (later)     | `request`            | 8    |
| (later)     | `form`               | 8    |
| (later)     | `get`                | 8    |

So you get one long list of tokens (exact split may vary slightly). Tokenization matches the training pipeline (same as `myutils.getTokens` in the reference repo).

---

## Step 2: Sliding windows

- The model was trained on **windows** of 200 tokens (`WINDOW_LENGTH = 200`).
- The window **steps by 5 tokens** each time (`WINDOW_STEP = 5`).
- Your file might have ~50 tokens, so there is **one window** (tokens 0 to end). That window is **padded with zeros** up to length 200.

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
# Model may output logits (no sigmoid in saved graph). Convert to probability like XSS/command injection.
prob = float(1.0 / (1.0 + np.exp(-np.clip(raw, -709.0, 709.0))))
```

- The saved CSRF BiLSTM may have a final layer **without** sigmoid, so it can output a **raw score (logit)**.
- The scanner applies **sigmoid** so that **prob** is in **[0, 1]** (consistent with XSS and command-injection scanners).
- High **prob** (e.g. 0.7) = “this window looks like CSRF”. Low (e.g. 0.3) = “unlikely”.

So for each window you get **one number** between 0 and 1.

---

## Step 5: Threshold and which lines to report

- Default threshold is **0.5**.
- If **prob ≥ 0.5**, the scanner does **not** just report the line where the window **starts**. Instead it looks at **all lines in that window** and reports only lines that look CSRF-relevant.

**Relevance scoring (`_csrf_relevance`):**

- A line gets a score ≥ 1 if it contains CSRF-related patterns, for example:
  - **Strong:** `request.method` with `POST`/`post`, `@app.route` (or `app.route`) with `POST`/`methods`, `csrf_exempt`.
  - **Form handling:** `request.form`, `request.POST`.
  - **HTML forms:** `<form`, `method=` with `post` or `action=`.
  - **Cookies:** `set_cookie` (session/CSRF context).
  - **AJAX/fetch:** `fetch(`, `$.ajax`, `axios.` with `POST` or `method:`.
- Docstrings and comments (`"""..."""`, `'''...'''`, `#`) get score **0** so they are not reported.
- If **no** line in the window has relevance ≥ 1, **nothing** is reported for that window (no fallback to the window-start line).

So for the example code:

- The window contains line 6: `@app.route('/submit', methods=['POST'])` → route + POST → relevance ≥ 1.
- Line 8: `data = request.form.get('data')` → `request.form` → relevance ≥ 1.
- The scanner reports **those lines** (and any other line in the window with relevance ≥ 1), not necessarily the window’s start line.

One vulnerability per reported line, e.g.:

- **Line:** 6 — **Description:** `"ML BiLSTM: potential CSRF vulnerability (confidence: 0.xx)"`  
- **Line:** 8 — same description, **Severity:** `"high"`, **Confidence:** prob (rounded)

---

## Step 6: Deduplicate by line

- Several overlapping windows can all have **prob ≥ 0.5** and can all suggest the **same line** (e.g. line 8).
- The scanner keeps **one result per line**: the one with the **highest confidence** for that line.

So the final list has **at most one** `CSRFVulnerability` per source line.

---

## Short summary for this exact code

| Step | What happens with this code |
|------|-----------------------------|
| 1    | File → list of tokens. |
| 2    | 1 window (or more for longer files), step 5. |
| 3    | Tokens → Word2Vec vectors, padded to 200×300 → **X** shape (1, 200, 300). |
| 4    | Model outputs **raw**; we apply **sigmoid** → **prob** in [0, 1]. |
| 5    | If prob ≥ 0.5, find all lines in the window with CSRF relevance ≥ 1; report those (e.g. lines 6, 8). |
| 6    | Deduplicate by line (keep highest confidence per line). |

**In one sentence:** The file is tokenized, **windows of 200 tokens slide 5 at a time**, each window gets **one prob** (after sigmoid); for every window with prob ≥ 0.5 we report **only lines inside that window that look CSRF-relevant**, then deduplicate by line.

---

# Second example: longer file, multiple windows

---

## Example source code

```python
def vulnerable_csrf_high_1():
    """Flask POST without CSRF protection"""
    @app.route('/submit', methods=['POST'])
    def submit_form():
        data = request.form.get('data')
        return "OK"

def vulnerable_csrf_high_2():
    """Django view with CSRF exemption"""
    from django.views.decorators.csrf import csrf_exempt

    @csrf_exempt
    def process_form(request):
        if request.method == 'POST':
            data = request.POST.get('data')
            return HttpResponse("OK")
```

---

## Step 1: Tokenize

The scanner turns the whole file into a flat list of tokens. For a file like this you get **100+ tokens** total.

---

## Step 2: Sliding windows

Same as XSS/command injection:

```
WINDOW_LENGTH = 200
WINDOW_STEP   =   5
```

- Window 1: tokens[0   : 200]  → starts at line ~1  
- Window 2: tokens[5   : 205]  → starts at line ~3  
- …

Each window **overlaps** the previous one. The model is called **once per window**.

---

## Step 3: Tokens → vectors → X

For each window: tokens → Word2Vec vectors → pad to 200 → **X** = shape `(1, 200, 300)`.

---

## Step 4: Model output and sigmoid

```python
raw = float(pred.ravel()[0])
prob = 1.0 / (1.0 + exp(-clip(raw, -709, 709)))
```

- **prob** is in [0, 1]. High value ⇒ “this window looks like CSRF”.

---

## Step 5: Which lines get reported (relevance, not just window start)

When **prob ≥ 0.5**, the scanner:

1. Computes the **line range** of the window (first token line → last token line).
2. Calls **`_relevant_lines_in_range(lines, line_start, line_end)`**: every line in that range whose **CSRF relevance** is ≥ 1.
3. For each of those lines it adds (or updates) a vulnerability in **by_line**, keeping the **highest confidence** if the same line is hit by several windows.

Example:

| Window | Start line | prob  | Lines in window with relevance ≥ 1 | Reported lines |
|--------|------------|-------|--------------------------------------|-----------------|
| 1      | 1          | 0.55  | 4, 6, 12, 15, 17                     | 4, 6, 12, 15, 17 |
| 2      | 3          | 0.52  | 6, 12, 15, 17                         | (update if higher conf) |
| …      | …          | …     | …                                    | …               |

- Line 4: `@app.route('/submit', methods=['POST'])` → route + POST.
- Line 6: `data = request.form.get('data')` → request.form.
- Line 12: `@csrf_exempt` → exemption (bad for CSRF).
- Line 15: `if request.method == 'POST':` → POST handling.
- Line 17: `data = request.POST.get('data')` → request.POST.

So the **reported line numbers** are the ones that **look like CSRF** inside the window.

---

## Step 6: Deduplicate by line

- Many windows can suggest the **same** line.
- For each line we keep **one** result: the one with the **highest confidence**.

```python
if line_number not in by_line or round(prob, 3) > by_line[line_number].confidence:
    by_line[line_number] = CSRFVulnerability(...)
```

Final list: **at most one** vulnerability per line, sorted by line number.

---

## Why we use relevance (and sigmoid)

1. **Sigmoid:** If the saved CSRF model has **no sigmoid** on the last layer, it outputs **logits**. Applying sigmoid in the scanner gives a proper probability in [0, 1] and a clear 0.5 threshold (same as XSS/command injection).
2. **Relevance:** The model scores a **whole 200-token window**. It does not say “line 9 is the bug.” By reporting only lines **inside** the window that have CSRF-like patterns (POST handling, forms, csrf_exempt, request.form/POST, set_cookie, etc.), we:
   - Reduce noise (e.g. avoid reporting blank or comment lines).
   - Point the user at the lines that actually look like CSRF (state-changing operations, missing tokens, exemptions).

---

## Final result (example)

```
Total vulnerabilities: 5
[line 4]  high confidence=0.55: ML BiLSTM: potential CSRF vulnerability (confidence: 0.55)
[line 6]  high confidence=0.55: ML BiLSTM: potential CSRF vulnerability (confidence: 0.55)
[line 12] high confidence=0.55: ML BiLSTM: potential CSRF vulnerability (confidence: 0.55)
[line 15] high confidence=0.52: ML BiLSTM: potential CSRF vulnerability (confidence: 0.52)
[line 17] high confidence=0.52: ML BiLSTM: potential CSRF vulnerability (confidence: 0.52)
```

---

## One-sentence summary

> The file is tokenized, a **window of 200 tokens slides 5 tokens at a time**, each window is fed to the BiLSTM model and gets **one prob** (after sigmoid); every window with **prob ≥ 0.5** contributes reports only for **lines inside that window that have CSRF relevance ≥ 1**; then results are **deduplicated by line** (highest confidence kept).

---

## Summary of steps (full pipeline)

| Step | Description |
|------|-------------|
| 1 | Tokenize the file into a flat list of tokens (same style as training). |
| 2 | Sliding window: `WINDOW_LENGTH=200`, `WINDOW_STEP=5`. |
| 3 | Tokens → Word2Vec vectors → pad to 200 → **X** shape (1, 200, 300). |
| 4 | Model predicts one **raw** value per window; apply **sigmoid** → **prob** in [0, 1]. |
| 5 | If prob ≥ 0.5, collect all lines in the window with **CSRF relevance ≥ 1**; add/update them in **by_line** (keep highest confidence per line). |
| 6 | Output the list of vulnerabilities, one per line, sorted by line number. |
