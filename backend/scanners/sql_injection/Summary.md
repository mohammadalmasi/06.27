# ML SQL Injection Scanner Summary

The `ml_sql_injection_scanner.py` file is a machine-learning-based tool designed to detect SQL injection vulnerabilities in Python source code. It relies on a **Bidirectional LSTM (BiLSTM)** deep learning model combined with **Word2Vec** embeddings.

Here is a step-by-step breakdown of how the scanner works:

### 1. Model Loading
When the scanner initializes (in the `MLSQLInjectionDetector` class), it loads two pre-trained models:
- **BiLSTM Model:** A TensorFlow/Keras model (`bidirectional_LSTM_model_sql.h5`) that has been trained to recognize the patterns of vulnerable vs. safe code.
- **Word2Vec Model:** A Gensim model (e.g., `word2vec_withString10-200-300.model`) that maps source code text/symbols into meaningful numeric vectors.

### 2. Tokenizing the Source Code
When you pass a file or string of code to `scan_source()`, the first step is tokenization via the `tokenize_code()` function. 
It breaks the code down into tiny chunks or "tokens" (like `def`, `query`, `=`, `"SELECT * FROM"`, `+`). It pays special attention to split characters and delimiters like parentheses and spaces to match the exact format the AI model was originally trained on.

### 3. Converting Tokens to Vectors
Since neural networks cannot understand raw text, the script converts each token into a list of numbers (a vector) using the Word2Vec model via `tokens_to_vectors()`. If a token is unknown to the Word2Vec model, it is assigned an array of zeros.

### 4. The Sliding Window Approach
Instead of analyzing the entire file at once, the scanner breaks the tokens into chunks using a "sliding window":
- It takes a window of **200 tokens** (defined by `WINDOW_LENGTH`).
- It processes that chunk, and then slides forward by **5 tokens** (`WINDOW_STEP`) to grab the next chunk. 
This sliding approach ensures that a vulnerability isn't accidentally missed by being split down the middle of two separate chunks. 

### 5. Prediction (Scoring the Code)
For each chunk of 200 tokens, the code pads the data to ensure it is the perfect size and feeds it into the BiLSTM model:
```python
pred = self._model.predict(X, verbose=0)
prob = float(pred.ravel()[0])
```
The model outputs a probability score between `0.0` and `1.0`. This score answers the question: *"How likely is it that this chunk of code contains a SQL injection vulnerability?"*

### 6. Flagging Vulnerabilities
If the model's confidence score is greater than or equal to the `confidence_threshold` (which defaults to `0.5` or 50%), the script:
1. Maps the token's position back to the actual line number in the source code using `token_index_to_line_number()`.
2. Grabs the specific code snippet for context.
3. Appends it to a `vulnerabilities` list with a `high` severity rating and the calculated confidence score.

### Summary
In simple terms: it reads the Python code, splits it into words/symbols, turns those words into numbers, feeds them into an AI model in overlapping chunks, and flags any chunk where the AI predicts a high chance of a SQL injection.
