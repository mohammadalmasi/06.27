# How `ml_sql_injection_scanner.py` Works

The ML SQL injection scanner uses a **BiLSTM** (Bidirectional LSTM) neural network to detect potential SQL injection patterns in Python source code. It does not use regex or rule-based patterns; it uses the same tokenization → embedding → sequence-model pipeline the model was trained with.

---

## 1. Pipeline Overview

```
Python source file
    → Tokenize (_get_tokens)
    → Sliding windows of 200 tokens (step 5)
    → Tokens → vectors (_tokens_to_vectors, Word2Vec or zeros)
    → Pad to 200 × embed_dim
    → BiLSTM predict → probability
    → If prob ≥ threshold → report SQLInjectionVulnerability
    → Deduplicate by line
```

---

## 2. Step-by-Step

### 2.1 Tokenization (`tokenize_code` / `_get_tokens`)

- Tokenization **matches the training pipeline**: the same logic as **`getTokens`** from the [Python-Source-Code-Vulnerability-Detection](https://github.com/Tf-arch/Python-Source-Code-Vulnerability-Detection) repo’s `myutils.py` (normalize spaces around punctuation, then split on a fixed set of delimiters, keeping both words and delimiter characters as separate tokens).
- Produces a **list of token strings** in order (e.g. `['query', ' ', '=', ' ', "'SELECT", "'", ...]`).
- Using the same tokenization as training is **required** for meaningful BiLSTM scores; a different tokenizer (e.g. Python’s `tokenize`) yields low probabilities.

The model always sees code as a **sequence of tokens**, not raw text.

### 2.2 Embeddings (`_tokens_to_vectors`, Word2Vec)

- Each token is turned into a **fixed-size vector** (e.g. 300-D).
- If a **Word2Vec** model is loaded from `backend/models/wordtovec_models/`, known tokens get their Word2Vec vector; **unknown tokens** get a **zero vector**.
- If no Word2Vec is found, **all** tokens get zero vectors (scanner still runs, but the model has less signal).

So the neural net input is **sequences of vectors**, not strings.

### 2.3 Sliding Windows

- The full token list is split into **overlapping windows** of length **200** tokens, with **step 5** (same idea as in training).
- For each window: tokens → vectors, then **pad/truncate** to exactly **200 × embed_dim** (e.g. 200×300).
- Each such matrix is fed to the model once.

So the model never sees the whole file; it sees **fixed-length “snippets”** of 200 tokens.

### 2.4 BiLSTM Model

- **Model file:** `backend/models/bidirectional_LSTM_model_sql.h5`.
- **Input shape:** `(batch, 200, embed_dim)` (e.g. 200 timesteps, 300 features).
- **Output:** one scalar per window (probability that this window is “vulnerable”).
- **Threshold:** by default **0.5**. If `prob ≥ 0.5`, that window is reported as potential SQL injection.

### 2.5 Reporting and Deduplication

- For each window above threshold, the code figures an **approximate line number** for the start of that window (`_token_start_to_line` using `tokenize` again).
- It builds a **`SQLInjectionVulnerability`** (same type as the rule-based scanner) with line number, description (including confidence), severity, code snippet, remediation, and confidence = that probability.
- **Deduplication:** several windows can point to the same line. The scanner **merges by line** and keeps the **highest confidence** per line.

So the **output** is a list of **`SQLInjectionVulnerability`** objects, one per “affected” line (at most), with confidence and snippet.

---

## 3. Main Components

| Component | Role |
|-----------|------|
| **`MLSQLInjectionDetector`** | Holds model path, optional Word2Vec path, threshold, step, max_length. Loads model (and optionally Word2Vec) on first use (`_ensure_loaded`). **`scan_file(filename)`** runs the full pipeline on a file and returns a list of `SQLInjectionVulnerability`. |
| **`scan_code_content_for_sql_injection_ml(code_content, source_name, ...)`** | Writes `code_content` to a temp `.py` file, runs `MLSQLInjectionDetector().scan_file(...)` on it, then returns the **same kind of result dict** as the rule-based scanner (e.g. for API use): `vulnerabilities`, `summary`, `scan_type`, etc. |

---

## 4. Legacy Model Loading (Keras 3)

The `.h5` was saved with an older Keras that put **`batch_input_shape`** and **`time_major`** in the LSTM config. Keras 3 does not accept those. The script **monkey-patches** `LSTM.from_config` to **remove** those two keys before building the layer, so the existing `bidirectional_LSTM_model_sql.h5` loads without changing the file.

---

## 5. End-to-End Flow (One File)

1. Read file → get **code** and **lines**.
2. **Tokenize** code → **tokens**.
3. For each **window** of 200 tokens (step 5):
   - **Tokens → vectors** (Word2Vec or zeros).
   - **Pad** to (200, embed_dim).
   - **BiLSTM predict** → one probability.
   - If **prob ≥ 0.5** → create **SQLInjectionVulnerability** (line, snippet, confidence).
4. **Deduplicate** by line (keep max confidence).
5. Return list of **`SQLInjectionVulnerability`** (or, if using the helper, the same structure as the rule-based scanner).

---

## 6. Usage

**Scan a file:**

```python
from scanners.sql_injection.ml_sql_injection_scanner import MLSQLInjectionDetector

detector = MLSQLInjectionDetector()
vulnerabilities = detector.scan_file("/path/to/file.py")
```

**Scan a code string (e.g. for API):**

```python
from scanners.sql_injection.ml_sql_injection_scanner import scan_code_content_for_sql_injection_ml

results = scan_code_content_for_sql_injection_ml(code_content, "Direct input")
# results: vulnerabilities, summary, scan_type, etc.
```

**Word2Vec (required for useful predictions):** The BiLSTM was trained with **`word2vec_withString10-200-300.model`** (from the repo’s Train-model.py: min_count=10, iterations=200, size=300). This is the **supported model** for best detection. Place it in `backend/models/` or `backend/models/wordtovec_models/`. Without it, tokens are embedded as zeros and predictions are not reliable. Use `test_ml_sql_word2vec_models.py` to compare models (only 300-dim models are run).

---

## 7. Summary

**`ml_sql_injection_scanner.py`** turns Python code into token sequences, embeds them (Word2Vec or zeros), runs fixed-length windows through a BiLSTM trained to detect SQL injection, and reports findings as **`SQLInjectionVulnerability`** objects keyed by line.
