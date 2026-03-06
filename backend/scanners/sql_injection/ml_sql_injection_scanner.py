# =============================================================================
# ML SQL INJECTION SCANNER
# =============================================================================
# What this file does (in simple words):
#
#   1. Read a Python file.
#   2. Split the code into small words (tokens), e.g. "def", "query", "=", "+"
#   3. Turn each token into a list of numbers (vector). using Word2Vec model
#   4. Take chunks of 200 tokens, pad them to same length, and send each chunk
#      to the BiLSTM model. The model answers: "How likely is this chunk
#      vulnerable?" (a number between 0 and 1).
#   5. If the number is >= 0.5 we say "potential SQL injection" and report the
#      line. We then remove duplicates (same line reported more than once).
# =============================================================================

import os
import re
import tokenize
import io
import numpy as np
from pathlib import Path

# -----------------------------------------------------------------------------
# PART 1: Load TensorFlow/Keras (needed for the BiLSTM model)
# -----------------------------------------------------------------------------
try:
    from tensorflow.keras import layers
    from tensorflow.keras.models import load_model as _keras_load_model
    from tensorflow.keras.preprocessing.sequence import pad_sequences

    # Old .h5 files saved "batch_input_shape" in LSTM; Keras 3 does not allow it.
    # We patch LSTM.from_config to remove that so our model can load.
    _original_lstm_from_config = layers.LSTM.from_config.__func__

    @classmethod
    def _patched_lstm_from_config(cls, config):
        config = dict(config)
        config.pop("batch_input_shape", None)
        config.pop("time_major", None)
        return _original_lstm_from_config(cls, config)

    layers.LSTM.from_config = _patched_lstm_from_config

    def _load_keras_model(path):
        return _keras_load_model(path)

    HAS_KERAS = True
except ImportError:
    HAS_KERAS = False
    _load_keras_model = None

# -----------------------------------------------------------------------------
# PART 2: Load Word2Vec (optional; makes predictions better)
# -----------------------------------------------------------------------------
try:
    from gensim.models import Word2Vec
    HAS_GENSIM = True
except ImportError:
    HAS_GENSIM = False

# We use the same "vulnerability" object as the rule-based SQL scanner.
from scanners.sql_injection.sql_injection_scanner import SQLInjectionVulnerability

# Where files live
BACKEND_DIR = Path(__file__).resolve().parent.parent.parent
MODEL_DIR = BACKEND_DIR / "models"
DEFAULT_MODEL_PATH = MODEL_DIR / "bidirectional_LSTM_model_sql.h5"
WORD2VEC_DIR = MODEL_DIR / "wordtovec_models"

# Model expects chunks of 200 tokens; we move by 5 tokens each time (sliding window).
WINDOW_LENGTH = 200
WINDOW_STEP = 5
EMBED_DIM = 300  # Size of each token vector; we read real value from model if needed.

# Word2Vec the BiLSTM was trained with (from Train-model.py: mincount=10, iterations=200, size=300).
# Use this exact model for correct embeddings. Others with dim=300 may work but can give worse results.
REQUIRED_WORD2VEC_FILENAME = "word2vec_withString10-200-300.model"
DEFAULT_WORD2VEC_PATH = MODEL_DIR / REQUIRED_WORD2VEC_FILENAME


# =============================================================================
# PART 3: Helper functions (tokenize, vectors, load Word2Vec)
# =============================================================================

def tokenize_code(code):
    """
    Tokenize source code the same way as the repo's myutils.getTokens (used to train
    the BiLSTM and Word2Vec). Splits on splitchars and keeps delimiters as tokens.
    """
    if not code:
        return []
    change = code
    change = change.replace(" .", ".")
    change = change.replace(" ,", ",")
    change = change.replace(" )", ")")
    change = change.replace(" (", "(")
    change = change.replace(" ]", "]")
    change = change.replace(" [", "[")
    change = change.replace(" {", "{")
    change = change.replace(" }", "}")
    change = change.replace(" :", ":")
    change = change.replace("- ", "-")
    change = change.replace("+ ", "+")
    change = change.replace(" =", "=")
    change = change.replace("= ", "=")
    splitchars = [
        " ", "\t", "\n", ".", ":", "(", ")", "[", "]", "<", ">", "+", "-", "=",
        '"', "'", "*", "/", "\\", "~", "{", "}", "!", "?", ";", ",", "%", "&",
    ]
    tokens = []
    start = 0
    end = 0
    for i in range(len(change)):
        if change[i] in splitchars:
            if i > start:
                end = i
                if start == 0:
                    token = change[:end]
                else:
                    token = change[start:end]
                if len(token) > 0:
                    tokens.append(token)
                tokens.append(change[i])
            else:
                tokens.append(change[i])
            start = i + 1
    if start < len(change):
        token = change[start:]
        if len(token) > 0:
            tokens.append(token)
    return tokens


def load_word2vec(w2v_path=None, embed_dim=None):
    """
    Try to load a Word2Vec model from backend/models/ or backend/models/wordtovec_models/.
    Returns (model or None, embed_dim). If no model found, we use zeros for tokens.
    """
    if not HAS_GENSIM:
        return None, embed_dim or EMBED_DIM
    # Single file path given by user
    if w2v_path and Path(w2v_path).is_file():
        try:
            w2v = Word2Vec.load(str(w2v_path))
            return w2v, w2v.wv.vector_size
        except Exception:
            pass
    # First: the exact model the BiLSTM was trained with (Train-model.py).
    # Then: other 300-dim models as fallback.
    w2v_filenames = [
        REQUIRED_WORD2VEC_FILENAME,
        "word2vec_withString50-50-300.model",
        "word2vec_withString10-200-200.model",
    ]
    # Try backend/models/ first (where user placed the file), then wordtovec_models/
    for dir_path in (MODEL_DIR, WORD2VEC_DIR):
        if not dir_path or not dir_path.is_dir():
            continue
        for name in w2v_filenames:
            full = dir_path / name
            if full.is_file():
                try:
                    w2v = Word2Vec.load(str(full))
                    return w2v, w2v.wv.vector_size
                except Exception:
                    continue
    return None, embed_dim or EMBED_DIM


def token_to_vector(token, w2v_model, embed_dim, zero_vec):
    """
    Turn one token (string) into one vector (list of numbers).
    If token is in Word2Vec we use its vector; else we use zero_vec.
    """
    if not token or token == " ":
        return None
    if w2v_model is None:
        return zero_vec
    wv = w2v_model.wv
    # Gensim 4.x
    if hasattr(wv, "key_to_index"):
        if token in wv.key_to_index:
            return wv.get_vector(token).astype(np.float32)
        return zero_vec
    # Older gensim
    if hasattr(wv, "vocab") and token in wv.vocab:
        return np.asarray(w2v_model[token], dtype=np.float32)
    return zero_vec


def tokens_to_vectors(tokens, w2v_model, embed_dim):
    """
    Turn a list of tokens into a list of vectors (each vector length embed_dim).
    Unknown tokens become a zero vector.
    """
    zero_vec = np.zeros(embed_dim, dtype=np.float32)
    result = []
    for t in tokens:
        v = token_to_vector(t, w2v_model, embed_dim, zero_vec)
        if v is not None:
            result.append(v)
    return result


def token_index_to_line_number(code, token_index):
    """
    Given "position in the token list", find which line in the source that is.
    """
    count = 0
    try:
        stream = io.BytesIO(code.encode("utf-8")).readline
        for tok in tokenize.tokenize(stream):
            if tok.type == tokenize.ENCODING:
                continue
            if count >= token_index:
                return max(1, tok.start[0])
            count += 1
    except Exception:
        pass
    return 1


# =============================================================================
# PART 4: The main detector class
# =============================================================================

class MLSQLInjectionDetector:
    """
    Scans a Python file for SQL injection using the BiLSTM model.
    Use: detector = MLSQLInjectionDetector(); detector.scan_file("file.py")
    """

    def __init__(
        self,
        model_path=None,
        w2v_path=None,
        confidence_threshold=0.5,
        verbose=False,
    ):
        self.model_path = model_path or str(DEFAULT_MODEL_PATH)
        # Use word2vec_withString10-200-300.model by default when the file exists
        if w2v_path is not None:
            self.w2v_path = w2v_path
        elif DEFAULT_WORD2VEC_PATH.is_file():
            self.w2v_path = str(DEFAULT_WORD2VEC_PATH)
        else:
            self.w2v_path = None
        self.confidence_threshold = confidence_threshold
        self.verbose = verbose
        # Loaded lazily on first scan
        self._model = None
        self._w2v = None
        self._window_length = WINDOW_LENGTH
        self._embed_dim = EMBED_DIM
        self.vulnerabilities = []

    def _load_model_and_w2v(self):
        """Load the .h5 model and (optional) Word2Vec once."""
        if self._model is not None:
            return
        if self.verbose:
            print("[ML SQL] Loading model and Word2Vec...")
        if not HAS_KERAS:
            raise RuntimeError("ML SQL scanner needs TensorFlow. Run: pip install tensorflow")
        if not os.path.isfile(self.model_path):
            raise FileNotFoundError(
                f"Model not found: {self.model_path}. "
                "Put bidirectional_LSTM_model_sql.h5 in backend/models/."
            )
        self._model = _load_keras_model(self.model_path)
        # Read expected size from model: (batch, time_steps, features)
        if self._model.input_shape and len(self._model.input_shape) >= 3:
            self._window_length = int(self._model.input_shape[1])
            self._embed_dim = int(self._model.input_shape[2])
        self._w2v, _ = load_word2vec(self.w2v_path, self._embed_dim)
        if self.verbose:
            print(f"[ML SQL] Model loaded. Window length={self._window_length}, embed_dim={self._embed_dim}")
            if self._w2v is not None:
                print("[ML SQL] Word2Vec: loaded")
            else:
                if not HAS_GENSIM:
                    print("[ML SQL] Word2Vec: not found (install gensim: pip install gensim)")
                else:
                    print(f"[ML SQL] Word2Vec: not found (using zero vectors). Put {REQUIRED_WORD2VEC_FILENAME} in backend/models/")

    def scan_source(self, source_code, source_name="<source>"):
        """
        Scan a source code string directly. Returns a list of SQLInjectionVulnerability.
        """
        self.vulnerabilities = []
        self._load_model_and_w2v()
        return self._scan_code(source_code, source_name)

    def scan_file(self, filename):
        """
        Scan a Python file. Returns a list of SQLInjectionVulnerability.
        """
        self.vulnerabilities = []
        self._load_model_and_w2v()

        try:
            with open(filename, "r", encoding="utf-8") as f:
                code = f.read()
        except UnicodeDecodeError:
            with open(filename, "r", encoding="latin-1") as f:
                code = f.read()
        return self._scan_code(code, filename)

    def _scan_code(self, code, source_name):
        """
        Core scanning logic shared by scan_file and scan_source.
        """
        lines = code.split("\n")
        if self.verbose:
            print(f"[ML SQL] Step 1: Read source — {len(lines)} lines")

        # Step 2: Tokenize
        tokens = tokenize_code(code)
        if not tokens:
            if self.verbose:
                print("[ML SQL] Step 2: Tokenize — no tokens, skipping")
            return []
        if self.verbose:
            print(f"[ML SQL] Step 2: Tokenize — {len(tokens)} tokens")

        # Step 3: Sliding windows of 200 tokens
        num_windows = len(range(0, max(1, len(tokens) - self._window_length + 1), WINDOW_STEP))
        if self.verbose:
            print(f"[ML SQL] Step 3: Processing {num_windows} windows (length={self._window_length}, step={WINDOW_STEP})")
        window_index = 0
        for start in range(0, max(1, len(tokens) - self._window_length + 1), WINDOW_STEP):
            end = min(start + self._window_length, len(tokens))
            chunk = tokens[start:end]

            # Step 4: Tokens -> vectors, then pad to fixed length
            vecs = tokens_to_vectors(chunk, self._w2v, self._embed_dim)
            if not vecs:
                continue
            seq = np.array(vecs, dtype=np.float32)
            X = pad_sequences(
                [seq],
                maxlen=self._window_length,
                dtype="float32",
                padding="post",
                truncating="post",
            )
            X = np.asarray(X).astype(np.float32)

            # Step 5: Ask the model: is this chunk vulnerable?
            pred = self._model.predict(X, verbose=0)
            prob = float(pred.ravel()[0])

            if self.verbose:
                line_number = token_index_to_line_number(code, start)
                print(f"[ML SQL]   Window {window_index + 1}/{num_windows}: tokens [{start}:{end}] -> line ~{line_number}, prob={prob:.3f}")
            window_index += 1

            if prob >= self.confidence_threshold:
                line_number = token_index_to_line_number(code, start)
                snippet = self._get_line(lines, line_number) or " ".join(chunk[:30])
                if self.verbose:
                    print(f"[ML SQL]   -> VULNERABILITY at line {line_number} (confidence={prob:.2f})")
                self.vulnerabilities.append(
                    SQLInjectionVulnerability(
                        line_number=line_number,
                        vulnerability_type="sql_injection",
                        description=f"ML BiLSTM: potential SQL injection (confidence: {prob:.2f})",
                        severity="high",
                        code_snippet=snippet,
                        remediation="Use parameterized queries and avoid string concatenation for SQL.",
                        confidence=round(prob, 3),
                        file_path=source_name,
                    )
                )

        # Step 6: One report per line (keep highest confidence)
        result = self._deduplicate_by_line(self.vulnerabilities)
        if self.verbose:
            print(f"[ML SQL] Step 6: Deduplicate — {len(self.vulnerabilities)} raw -> {len(result)} vulnerabilities")
        return result

    def _get_line(self, lines, line_number):
        """Get the text of line number (1-based)."""
        if not lines or line_number < 1 or line_number > len(lines):
            return ""
        return lines[line_number - 1].strip()

    def _deduplicate_by_line(self, vuln_list):
        """If same line appears several times, keep only the one with highest confidence."""
        if not vuln_list:
            return []
        by_line = {}
        for v in vuln_list:
            ln = v.line_number
            if ln not in by_line or v.confidence > by_line[ln].confidence:
                by_line[ln] = v
        return list(by_line.values())


# =============================================================================
# PART 5: API-style function (scan a string of code, return a dict like the API)
# =============================================================================

def scan_code_content_for_sql_injection_ml(
    code_content: str,
    source_name: str,
    model_path=None,
    w2v_path=None,
    verbose=False,
    confidence_threshold=0.5,
) -> dict:
    """
    Scan a string of code (e.g. from an API). Returns a dict with
    'vulnerabilities', 'summary', 'scan_type', etc. Same shape as the
    rule-based SQL scanner result.
    """
    from datetime import datetime
    import tempfile

    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as f:
            f.write(code_content)
            temp_path = f.name
        if verbose:
            print("[ML SQL] Scanning code content (temp file)...")
        detector = MLSQLInjectionDetector(
            model_path=model_path,
            w2v_path=w2v_path,
            verbose=verbose,
            confidence_threshold=confidence_threshold,
        )
        vulnerabilities = detector.scan_file(temp_path)
        os.unlink(temp_path)
    except Exception as e:
        return _error_result(source_name, code_content, str(e))

    summary = _make_summary(vulnerabilities)
    file_name = source_name.split("/")[-1] if "/" in source_name else source_name
    if source_name.startswith("http") and "/" in source_name:
        file_name = source_name.split("/")[-1]

    return {
        "source": source_name,
        "scan_type": "sql_injection_ml",
        "summary": summary,
        "vulnerabilities": [v.to_dict() for v in vulnerabilities],
        "total_vulnerabilities": len(vulnerabilities),
        "scan_timestamp": datetime.now().isoformat(),
        "total_issues": len(vulnerabilities),
        "high_severity": summary["high_severity"],
        "medium_severity": summary["medium_severity"],
        "low_severity": summary["low_severity"],
        "high_count": summary["high"],
        "medium_count": summary["medium"],
        "low_count": summary["low"],
        "highlighted_code": None,
        "original_code": code_content,
        "file_name": file_name,
    }


def _error_result(source_name, code_content, error_message):
    """Build the same dict shape when an error happens."""
    return {
        "error": f"Error during ML SQL injection scan: {error_message}",
        "source": source_name,
        "scan_type": "sql_injection_ml",
        "vulnerabilities": [],
        "total_vulnerabilities": 0,
        "total_issues": 0,
        "high_severity": 0,
        "medium_severity": 0,
        "low_severity": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "highlighted_code": None,
        "original_code": code_content,
        "file_name": source_name,
    }


def _make_summary(vulnerabilities):
    """Count high/medium/low severities."""
    return {
        "total_vulnerabilities": len(vulnerabilities),
        "high_severity": sum(1 for v in vulnerabilities if v.severity == "high"),
        "medium_severity": sum(1 for v in vulnerabilities if v.severity == "medium"),
        "low_severity": sum(1 for v in vulnerabilities if v.severity == "low"),
        "high": sum(1 for v in vulnerabilities if v.severity == "high"),
        "medium": sum(1 for v in vulnerabilities if v.severity == "medium"),
        "low": sum(1 for v in vulnerabilities if v.severity == "low"),
    }

if __name__ == "__main__":
    import sys
    import tempfile

    mode = sys.argv[1]
    argument = sys.argv[2]

    detector = MLSQLInjectionDetector()

    if mode == "0":
        print(f"00000")
        # mode 0 → scan a .py file
        vulns = detector.scan_file(argument)

    elif mode == "1":
        # mode 1 → scan source code string
        print(f"11111")

    else:
        print("Unknown mode. Use 0 for file, 1 for source code.")
        sys.exit(1)

    print("Vulnerabilities found:", len(vulns))
    for v in vulns:
        print("  Line", v.line_number, ":", v.description, "| confidence:", v.confidence)
