# =============================================================================
# ML CSRF SCANNER
# =============================================================================
# What this file does (in simple words):
#
#   1. Read a Python file.
#   2. Split the code into small words (tokens), e.g. "def", "request", ".", "args", ".", "get", "(", "\"csrf_token\"", ")", "return", "f\"", "<input type=\"hidden\" name=\"csrf_token\" value=\"{csrf_token}\">",
#   3. Turn each token into a list of numbers (vector). using Word2Vec model
#   4. Take chunks of 200 tokens, pad them to same length, and send each chunk
#      to the BiLSTM model. The model answers: "How likely is this chunk
#      vulnerable?" (a number between 0 and 1).
#   5. If the number is >= 0.5 we say "potential CSRF" and report the
#      line.
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

# Where files live
BACKEND_DIR = Path(__file__).resolve().parent.parent.parent
MODEL_DIR = BACKEND_DIR / "models"
DEFAULT_MODEL_PATH = MODEL_DIR / "bidirectional_LSTM_model_xsrf.h5"
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


def _github_blob_to_raw(url):
    """
    Convert GitHub blob URL to raw content URL.
    e.g. https://github.com/owner/repo/blob/branch/path/file.py
     -> https://raw.githubusercontent.com/owner/repo/branch/path/file.py
    """
    m = re.match(
        r"https?://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.+)",
        url.strip(),
        re.IGNORECASE,
    )
    if m:
        owner, repo, branch, path = m.groups()
        return f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
    return url


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
            print("[ML CSRF] Loading model and Word2Vec...")
        if not HAS_KERAS:
            raise RuntimeError("ML CSRF scanner needs TensorFlow. Run: pip install tensorflow")
        if not os.path.isfile(self.model_path):
            raise FileNotFoundError(
                f"Model not found: {self.model_path}. "
                "Put bidirectional_LSTM_model_xsrf.h5 in backend/models/."
            )
        self._model = _load_keras_model(self.model_path)
        # Read expected size from model: (batch, time_steps, features)
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

        # Step 2: Tokenize
        tokens = tokenize_code(source_code)
        if not tokens:
            if self.verbose:
                print("[ML CSRF] Step 2: Tokenize — no tokens, skipping")
            return []
        if self.verbose:
            print(f"[ML CSRF] Step 2: Tokenize — {len(tokens)} tokens")

        # Step 3: Sliding windows of 200 tokens
        num_windows = len(range(0, max(1, len(tokens) - self._window_length + 1), WINDOW_STEP))
        if self.verbose:
            print(f"[ML CSRF] Step 3: Processing {num_windows} windows (length={self._window_length}, step={WINDOW_STEP})")
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
            
            # ALWAYS print the probability for debugging purposes
            line_number = token_index_to_line_number(source_code, start)
            print(f"[DEBUG ML CSRF] Window starting at line {line_number} has prob: {prob:.6f}")

            if self.verbose:
                line_number = token_index_to_line_number(source_code, start)
                print(f"[ML CSRF]   Window {window_index + 1}/{num_windows}: tokens [{start}:{end}] -> line ~{line_number}, prob={prob:.3f}")
            window_index += 1

            if prob >= self.confidence_threshold:
                line_number = token_index_to_line_number(source_code, start)
                snippet = self._get_line(lines, line_number) or " ".join(chunk[:30])
                if self.verbose:
                    print(f"[ML CSRF]   -> VULNERABILITY at line {line_number} (confidence={prob:.2f})")
                self.vulnerabilities.append({
                    "line_number": line_number,
                    "severity": "high",
                    "code_snippet": snippet,
                    "confidence": round(prob, 3),
                })

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
        """
        Fetch source code from a URL and scan it. Supports GitHub blob URLs
        (converted to raw automatically). Raises URLError/HTTPError on fetch failure.
        """
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