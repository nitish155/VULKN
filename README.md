# VULKN

AI Based Web Application Security Scanner

## 👥 Team

| Name     | Role                       |
| -------- | -------------------------- |
| Yuvraj   | ML / AI Engineer           |
| Nitish   | Backend / Scanner Engineer |
| Sayantan | DevOps / Cloud Engineer    |
| Shreyasi | Frontend / Auth Engineer   |

---

## ML/AI Service — Person 1 (Week 2–3 Mini Project)

### What I built

An unsupervised anomaly detection system for HTTP web traffic.
Given an HTTP request's features, the model classifies it as
**normal** or **anomalous** (potential attack).

### Algorithm

**Isolation Forest** (sklearn.ensemble.IsolationForest)

Isolation Forest builds 100 random trees from normal traffic.
Normal requests are hard to isolate (many cuts needed) → high score.
Attack requests are easy to isolate (few cuts needed) → low score.
Any request with score below the threshold is flagged as anomalous.

### Dataset

**HTTP CSIC 2010** — 61,065 real HTTP requests

- 36,000 normal requests (58.9%)
- 25,065 attack requests: SQL injection, XSS, path traversal,
  buffer overflow, CSRF, parameter tampering (41.1%)
- Source: Spanish National Research Council (CSIC)

### Features (4 numeric features per request)

| Feature        | Source column | How computed                      |
| -------------- | ------------- | --------------------------------- |
| request_length | URL           | len(url) after stripping HTTP/1.1 |
| method_encoded | Method        | GET=0, POST=1, PUT=2              |
| num_parameters | URL           | count of & in query string        |
| body_length    | content       | len(body), 0 if null              |

### Results

| Contamination | Attacks caught | Recall    | False alarms | Precision |
| ------------- | -------------- | --------- | ------------ | --------- |
| 0.05          | 4,623          | 18.4%     | 1,618        | 74.1%     |
| **0.10**      | **7,719**      | **30.8%** | **3,563**    | **68.4%** |
| 0.20          | 11,280         | 45.0%     | 6,264        | 64.3%     |

**Chosen: contamination=0.10** — best balance for a security tool
where missing attacks (false negatives) is worse than false alarms.

### What I learned

1. **Isolation Forest** is better than supervised classification for
   security because it does not require labelled attack data.
   New attack types it has never seen are still detected if they
   differ from normal traffic patterns.

2. **Feature engineering matters more than the algorithm.**
   With 4 simple numeric features, recall is only 30%. Adding
   features like response_time and error_keywords (planned Week 6)
   will significantly improve this.

3. **The precision-recall tradeoff is a real engineering decision.**
   Raising contamination catches more attacks but creates more false
   alarms. In security contexts, false negatives are usually worse
   than false positives — so I tuned toward higher recall.

4. **Pandas and sklearn have a clean integration.**
   The pipeline: CSV → Pandas DataFrame → feature engineering →
   sklearn IsolationForest → joblib.dump() is a standard pattern
   I will reuse throughout VULKN.

### Saved model

`datasets/isolation_forest_final.joblib` — loaded by
`ai_service/main.py` on Day 18 for real-time classification.

### Notebooks

| Notebook                 | Purpose                           |
| ------------------------ | --------------------------------- |
| day11_csic_explore.ipynb | Dataset exploration and EDA       |
| day12_preprocess.ipynb   | Feature engineering               |
| day13_train_model.ipynb  | Isolation Forest training         |
| day14_evaluate.ipynb     | Contamination tuning + evaluation |
| day15_demo.ipynb         | Clean demo notebook for team      |
