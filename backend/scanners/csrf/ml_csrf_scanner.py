# =============================================================================
# ML CSRF SCANNER
# =============================================================================
# What this file does (in simple words):
#
#   1. Read a Python file.
#   2. Split the code into small words (tokens), e.g. "def", "request", ".", "form"
#   3. Turn each token into a list of numbers (vector), using Word2Vec model.
#   4. Take chunks of 200 tokens, pad them to same length, and send each chunk
#      to the BiLSTM model. The model answers: "How likely is this chunk
#      vulnerable?" (a number between 0 and 1).
#   5. If the number is >= 0.5 we say "potential CSRF" and report the line.
# =============================================================================

import io
import os
import re
import tokenize
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

import numpy as np

# -----------------------------------------------------------------------------
# PART 1: Load TensorFlow/Keras (needed for the BiLSTM model)
# -----------------------------------------------------------------------------
try:
    from tensorflow.keras import layers
    from tensorflow.keras.models import load_model as _keras_load_model
    from tensorflow.keras.preprocessing.sequence import pad_sequences

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

from scanners.csrf.csrf_scanner import CSRFVulnerability

# Where files live
BACKEND_DIR = Path(__file__).resolve().parent.parent.parent
MODEL_DIR = BACKEND_DIR / "models"
DEFAULT_MODEL_PATH = MODEL_DIR / "bidirectional_LSTM_model_xsrf.h5"
WORD2VEC_DIR = MODEL_DIR / "wordtovec_models"

WINDOW_LENGTH = 200
WINDOW_STEP = 5
EMBED_DIM = 300

REQUIRED_WORD2VEC_FILENAME = "word2vec_withString10-200-300.model"
DEFAULT_WORD2VEC_PATH = MODEL_DIR / REQUIRED_WORD2VEC_FILENAME


# =============================================================================
# PART 3: Helper functions (tokenize, vectors, load Word2Vec)
# =============================================================================

def tokenize_code(code):
    """Tokenize source code the same way as the repo's myutils.getTokens."""
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
    """Load Word2Vec model; returns (model or None, embed_dim)."""
    if not HAS_GENSIM:
        return None, embed_dim or EMBED_DIM
    if w2v_path and Path(w2v_path).is_file():
        try:
            w2v = Word2Vec.load(str(w2v_path))
            return w2v, w2v.wv.vector_size
        except Exception:
            pass
    w2v_filenames = [
        REQUIRED_WORD2VEC_FILENAME,
        "word2vec_withString50-50-300.model",
        "word2vec_withString10-200-200.model",
    ]
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
    """Turn one token into one vector."""
    if not token or token == " ":
        return None
    if w2v_model is None:
        return zero_vec
    wv = w2v_model.wv
    if hasattr(wv, "key_to_index"):
        if token in wv.key_to_index:
            return wv.get_vector(token).astype(np.float32)
        return zero_vec
    if hasattr(wv, "vocab") and token in wv.vocab:
        return np.asarray(w2v_model[token], dtype=np.float32)
    return zero_vec


def tokens_to_vectors(tokens, w2v_model, embed_dim):
    """Turn a list of tokens into a list of vectors."""
    zero_vec = np.zeros(embed_dim, dtype=np.float32)
    result = []
    for t in tokens:
        v = token_to_vector(t, w2v_model, embed_dim, zero_vec)
        if v is not None:
            result.append(v)
    return result


def token_index_to_line_number(code, token_index):
    """Given position in the token list, return the source line number."""
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


def _github_blob_to_raw(url):
    """Convert GitHub blob URL to raw content URL."""
    m = re.match(
        r"https?://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.+)",
        url.strip(),
        re.IGNORECASE,
    )
    if m:
        owner, repo, branch, path = m.groups()
        return f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
    return url


def _csrf_relevance(line_text):
    """Score how relevant a source line is to CSRF (higher = more likely vulnerable)."""
    if not line_text:
        return 0
    t = line_text.strip()
    # Ignore docstrings and comments
    if t.startswith('"""') or t.startswith("'''") or t.startswith("#"):
        return 0
    score = 0
    # Form / POST handling
    if "request.method" in t and ("POST" in t or "post" in t):
        score += 3
    if "request.form" in t or "request.POST" in t:
        score += 2
    if "@app.route" in t or "app.route" in t:
        if "POST" in t or "post" in t or "methods" in t:
            score += 3
        score += 1
    if "csrf_exempt" in t:
        score += 3
    if "<form" in t or "method=" in t or "method =" in t:
        if "post" in t.lower() or "action=" in t:
            score += 2
    if "set_cookie" in t:
        score += 1
    if "fetch(" in t or "$.ajax" in t or "axios." in t:
        if "POST" in t or "post" in t or "method:" in t:
            score += 2
    return score


def _relevant_lines_in_range(lines, line_start, line_end, min_relevance=1):
    """Return 1-based line numbers in [line_start, line_end] with CSRF relevance >= min_relevance."""
    result = []
    for i in range(max(0, line_start - 1), min(len(lines), line_end)):
        if _csrf_relevance(lines[i]) >= min_relevance:
            result.append(i + 1)
    return result


# =============================================================================
# PART 4: The main detector class
# =============================================================================

class MLCSRFDetector:
    def __init__(
        self,
        model_path=None,
        w2v_path=None,
        confidence_threshold=0.5,
        verbose=False,
    ):
        self.model_path = model_path or str(DEFAULT_MODEL_PATH)
        if w2v_path is not None:
            self.w2v_path = w2v_path
        elif DEFAULT_WORD2VEC_PATH.is_file():
            self.w2v_path = str(DEFAULT_WORD2VEC_PATH)
        else:
            self.w2v_path = None
        self.confidence_threshold = confidence_threshold
        self.verbose = verbose
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
            print("[ML CSRF] Loading model and Word2Vec...")
        if not HAS_KERAS:
            raise RuntimeError("ML CSRF scanner needs TensorFlow. Run: pip install tensorflow")
        if not os.path.isfile(self.model_path):
            raise FileNotFoundError(
                f"Model not found: {self.model_path}. "
                "Put bidirectional_LSTM_model_xsrf.h5 in backend/models/."
            )
        self._model = _load_keras_model(self.model_path)
        if self._model.input_shape and len(self._model.input_shape) >= 3:
            self._window_length = int(self._model.input_shape[1])
            self._embed_dim = int(self._model.input_shape[2])
        self._w2v, _ = load_word2vec(self.w2v_path, self._embed_dim)
        if self.verbose:
            print(f"[ML CSRF] Model loaded. Window length={self._window_length}, embed_dim={self._embed_dim}")
            if self._w2v is not None:
                print("[ML CSRF] Word2Vec: loaded")
            else:
                if not HAS_GENSIM:
                    print("[ML CSRF] Word2Vec: not found (install gensim: pip install gensim)")
                else:
                    print(f"[ML CSRF] Word2Vec: not found (using zero vectors). Put {REQUIRED_WORD2VEC_FILENAME} in backend/models/")

    def scan_source(self, source_code, source_name="<source>"):
        self.vulnerabilities = []
        self._load_model_and_w2v()

        lines = source_code.split("\n")
        if self.verbose:
            print(f"[ML CSRF] Step 1: Read source — {len(lines)} lines")

        tokens = tokenize_code(source_code)
        if not tokens:
            if self.verbose:
                print("[ML CSRF] Step 2: Tokenize — no tokens, skipping")
            return []
        if self.verbose:
            print(f"[ML CSRF] Step 2: Tokenize — {len(tokens)} tokens")

        num_windows = len(range(0, max(1, len(tokens) - self._window_length + 1), WINDOW_STEP))
        if self.verbose:
            print(f"[ML CSRF] Step 3: Processing {num_windows} windows (length={self._window_length}, step={WINDOW_STEP})")
        by_line = {}
        window_index = 0
        for start in range(0, max(1, len(tokens) - self._window_length + 1), WINDOW_STEP):
            end = min(start + self._window_length, len(tokens))
            chunk = tokens[start:end]

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

            pred = self._model.predict(X, verbose=0)
            raw = float(pred.ravel()[0])
            # Model may output logits (no sigmoid in saved graph). Convert to probability like XSS/command injection.
            prob = float(1.0 / (1.0 + np.exp(-np.clip(raw, -709.0, 709.0))))

            if self.verbose:
                line_number = token_index_to_line_number(source_code, start)
                print(f"[ML CSRF]   Window {window_index + 1}/{num_windows}: tokens [{start}:{end}] -> line ~{line_number}, prob={prob:.3f}")
            window_index += 1

            if prob >= self.confidence_threshold:
                line_start_num = token_index_to_line_number(source_code, start)
                line_end_num = token_index_to_line_number(source_code, end - 1)
                for line_number in _relevant_lines_in_range(lines, line_start_num, line_end_num):
                    if line_number not in by_line or round(prob, 3) > by_line[line_number].confidence:
                        snippet = self._get_line(lines, line_number) or " ".join(chunk[:30])
                        if self.verbose:
                            print(f"[ML CSRF]   -> VULNERABILITY at line {line_number} (confidence={prob:.2f})")
                        by_line[line_number] = CSRFVulnerability(
                            line_number=line_number,
                            severity="high",
                            description=f"ML BiLSTM: potential CSRF vulnerability (confidence: {prob:.2f})",
                            code_snippet=snippet,
                            confidence=round(prob, 3),
                            cwe_id="CWE-352",
                            rule_key="CSRF-GENERIC",
                        )

        self.vulnerabilities = [by_line[ln] for ln in sorted(by_line)]
        if self.verbose:
            print(f"[ML CSRF] Found {len(self.vulnerabilities)} vulnerabilities")
        return self.vulnerabilities

    def scan_file(self, filename):
        try:
            with open(filename, "r", encoding="utf-8") as f:
                code = f.read()
        except UnicodeDecodeError:
            with open(filename, "r", encoding="latin-1") as f:
                code = f.read()
        return self.scan_source(code, source_name=filename)

    def scan_url(self, url, timeout=30):
        """Fetch source from URL and scan it. Supports GitHub blob URLs."""
        fetch_url = _github_blob_to_raw(url)
        req = Request(fetch_url, headers={"User-Agent": "ML-CSRF-Scanner/1.0"})
        with urlopen(req, timeout=timeout) as resp:
            code = resp.read().decode("utf-8", errors="replace")
        return self.scan_source(code, source_name=url)

    def _get_line(self, lines, line_number):
        """Get the text of line number (1-based)."""
        if not lines or line_number < 1 or line_number > len(lines):
            return ""
        return lines[line_number - 1].strip()


if __name__ == "__main__":
    import sys

    mode = sys.argv[1]
    argument = sys.argv[2]

    detector = MLCSRFDetector()

    if mode == "0":
        vulns = detector.scan_source(argument)
    elif mode == "1":
        vulns = detector.scan_file(argument)
    elif mode == "2":
        vulns = detector.scan_url(argument)
    else:
        print("Unknown mode. Use 0 for source, 1 for file, 2 for URL.")
        sys.exit(1)

    print("Vulnerabilities found:", len(vulns))
    for v in vulns:
        print("  Line", v.line_number, ":", v.description, "| confidence:", v.confidence)
