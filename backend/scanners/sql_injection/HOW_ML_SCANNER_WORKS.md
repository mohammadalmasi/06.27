# How the ML SQL Injection Scanner Works

This document explains the step-by-step process of how the Machine Learning scanner detects SQL injection vulnerabilities, followed by concrete examples to show how these steps apply in practice. This structure gives you a clear overview of the theory first, making the examples easy to follow.

---

## Part 1: How the Scanner Works (The Steps)

### Step 1: Tokenization
The scanner reads the source code file and breaks it down into a flat list of tokens (words, symbols, operators, etc.).

### Step 2: Sliding Windows
The model does NOT process the whole file at once. Instead, it uses a **sliding window** approach to scan through the token list:
- `WINDOW_LENGTH = 200`: The model looks at a block of 200 tokens at a time.
- `WINDOW_STEP = 5`: The window moves forward by 5 tokens to create the next block.

Each window heavily overlaps with the previous one. The model evaluates each window independently.

### Step 3: Vectorization (Tokens → Vectors → Matrix)
For each window, the tokens must be converted into numerical representations that the neural network can understand:
1. Each token is looked up in a pre-trained **Word2Vec** model to get a vector of 300 numbers (e.g., `"query"` → `[0.12, -0.45, 0.87, ...]`). Unknown tokens become vectors of 300 zeros.
2. The vectors are stacked into a matrix: `[window_length, 300]`.
3. If the window has fewer than 200 tokens (e.g. at the end of a file or for a very short file), it is **padded** with zeros up to exactly 200 rows.
4. The matrix is wrapped in a batch dimension, resulting in a matrix `X` of shape `(1, 200, 300)` (1 sample, 200 time steps, 300 features per step).

### Step 4: Model Prediction
The prepared matrix `X` is fed into the ML model (a BiLSTM neural network). The model outputs a single probability score (`prob` between 0 and 1) representing the likelihood that this specific 200-token window contains an SQL injection pattern.

### Step 5: Threshold Check and Line Reporting
The scanner checks the prediction against a confidence threshold (default `0.5`):
- If `prob >= 0.5` (e.g., `0.97`), it flags a vulnerability.
- The **line number** reported is the line where the **first token** of that window is located.

*Note: The model does not pinpoint the exact line of the bug. It simply states: "The 200-token window that **starts at this line** looks suspicious."*

### Step 6: Deduplication
Because the window slides by only 5 tokens at a time, a single SQL injection block will often be captured by multiple overlapping windows. 
If multiple windows trigger a vulnerability and happen to start on the *exact same line*, the scanner deduplicates them and keeps only the report with the highest confidence score for that line.

---

## Part 2: Examples in Practice

Now let's trace some actual code through these steps.

### Example 1: A Short File (Single Window)

**Source Code:**
```python
def vulnerable_sql_high_1():
    """Direct string concatenation in SELECT"""
    user_id = request.form["user_id"]
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(query)
```

**Walkthrough:**

**1. Tokenize:** The scanner turns the whole file into a list of tokens (words/symbols). For this code it is roughly:

| Token index | Token                | Line |
|-------------|----------------------|------|
| 0           | `def`                | 1    |
| 1           | `vulnerable_sql_high_1` | 1  |
| 2           | `(`                  | 1    |
| 3           | `)`                  | 1    |
| 4           | `:`                  | 1    |
| 5           | `user_id`            | 3    |
| 6           | `=`                  | 3    |
| 7           | `request`            | 3    |
| ...         | ...                  | ...  |
| 33          | `query`              | 5    |
| 34          | `)`                  | 5    |

So you get one long list of about 35 tokens.

**2. Sliding Windows:** Since the total tokens (~35) is less than `WINDOW_LENGTH` (200), there is only **one window** (tokens 0 to 35).

**3. Vectorize:** The 35 tokens are converted to 300-dimension vectors and padded with zeros up to 200 length. `X` has shape `(1, 200, 300)`.

**4. Prediction:** The model evaluates this single window and outputs **one number**, e.g., `prob = 0.97`.

**5. Threshold & Line Reporting:** 0.97 ≥ 0.5, so a vulnerability is reported. The window starts at token index 0, which maps to **line 1**.

**6. Deduplication:** Only one report exists, so deduplication does nothing.

**Result:** A single vulnerability is reported for the file at line 1.

---

### Example 2: A Longer File (Multiple Overlapping Windows)

**Source Code:**
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

**1. Tokenize (Visualizing the Tokens and Lines):**
Imagine your tokens are numbered. Each token lives on a line:

```text
token 0  → line 1   → "def"
token 1  → line 1   → "vulnerable_sql_high_1"
...
token 10 → line 7   → "def"
token 11 → line 7   → "vulnerable_sql_high_2"
token 12 → line 7   → "("
token 13 → line 9   → "name"       ← SQL code starts here
token 14 → line 10  → "query"
token 15 → line 11  → "cursor"
...
```

**2. Sliding Windows (`step=5`):** 
The sliding window (step=5) creates these windows:

```text
Window 1: starts at token 0  (line 1)  → model gets tokens 0..199
Window 2: starts at token 5  (line 3)  → model gets tokens 5..204
Window 3: starts at token 10 (line 7)  → model gets tokens 10..209
Window 4: starts at token 13 (line 9)  → model gets tokens 13..212  ← SQL code inside
Window 5: starts at token 14 (line 10) → model gets tokens 14..213  ← SQL code inside
Window 6: starts at token 15 (line 11) → model gets tokens 15..214  ← SQL code inside
```

**3 & 4. Vectorize & Prediction:** 
Windows 4, 5, and 6 all contain the SQL injection code (because the window is 200 tokens wide and they all overlap). The model gives all of them a high probability:

```text
Window 4 → prob 0.97
Window 5 → prob 0.97
Window 6 → prob 0.969
```

**5. Threshold & Line Reporting:**
Because all three are ≥ 0.5, it reports 3 vulnerabilities. It reports the **start line** of each window:

- Window 4 reports a bug at **line 9**
- Window 5 reports a bug at **line 10**
- Window 6 reports a bug at **line 11**

**6. Deduplication:** 
Since these windows start on different lines (9, 10, 11), the line-based deduplication doesn't merge them. 

**Result:**
You get multiple reports on consecutive lines. The key point: All these windows contain the same SQL injection code because they overlap. The only difference between them is where they start. You get multiple reports for different lines — not because the model found separate bugs, but because overlapping windows all saw the same bug and each one reported its own start line.

---

## One-Sentence Summary

> The scanner tokenizes the file, slides a 200-token window across it (moving 5 tokens at a time), converts each window into a numerical matrix, asks the model for a probability, and reports the start line of any window scoring `prob >= 0.5`.
