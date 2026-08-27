import math
import time
import joblib
import pandas as pd

from collections import Counter
from typing import List, Dict, Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel


# ============================================================
# 1. N-GRAM CLASS
# ============================================================

class NgramScorer:

    def __init__(self, n=2):
        self.n = n
        self.probs = {}

    def fit(self, domains):
        pass

    def score(self, domain: str) -> float:

        core = (
            domain.rsplit(".", 1)[0]
            if "." in domain
            else domain
        )

        if len(core) < self.n:
            return 0.0

        score_val = 0.0

        for i in range(len(core) - self.n + 1):

            gram = core[i:i + self.n]

            p = self.probs.get(
                gram,
                1e-6
            )

            score_val += math.log10(p)

        return score_val / (
            len(core) - self.n + 1
        )


# ============================================================
# 2. FIX JOBLIB __main__ REFERENCE
# ============================================================

import __main__

__main__.NgramScorer = NgramScorer


# ============================================================
# 3. LOAD MODEL
# ============================================================

MODEL_FILE = "final_dga_model.joblib"

model_pipeline: Dict[str, Any] = {}

try:

    artifacts = joblib.load(
        MODEL_FILE
    )

    model_pipeline["model"] = (
        artifacts["model"]
    )

    model_pipeline["bigram_model"] = (
        artifacts["bigram_model"]
    )

    model_pipeline["trigram_model"] = (
        artifacts["trigram_model"]
    )

    model_pipeline["features"] = (
        artifacts["features"]
    )

    print(
        "DGA model loaded successfully."
    )

except Exception as e:

    print(
        "ERROR loading DGA model:"
    )

    print(e)


# ============================================================
# 4. FASTAPI
# ============================================================

app = FastAPI(
    title="DGA Detection API",
    version="1.0.0"
)


# ============================================================
# 5. FEATURE EXTRACTION
# ============================================================

def remove_tld(domain: str) -> str:

    parts = domain.rsplit(".", 1)

    return (
        parts[0]
        if len(parts) > 1
        else domain
    )


def extract_features(
    domain: str,
    bigram_model,
    trigram_model,
    feature_names
):

    core_domain = remove_tld(
        domain
    )

    domain_length = len(
        core_domain
    )

    if domain_length == 0:

        return pd.DataFrame(
            [[0] * len(feature_names)],
            columns=feature_names
        )

    digit_count = sum(
        c.isdigit()
        for c in core_domain
    )

    digit_ratio = (
        digit_count /
        domain_length
    )

    vowels = set(
        "aeiouy"
    )

    vowel_count = sum(
        1
        for c in core_domain
        if c in vowels
    )

    vowel_ratio = (
        vowel_count /
        domain_length
    )

    consonants = set(
        "bcdfghjklmnpqrstvwxz"
    )

    consonant_count = sum(
        1
        for c in core_domain
        if c in consonants
    )

    consonant_ratio = (
        consonant_count /
        domain_length
    )

    counts = Counter(
        core_domain
    )

    entropy = -sum(
        (count / domain_length)
        * math.log2(
            count / domain_length
        )
        for count in counts.values()
    )

    unique_char_ratio = (
        len(counts) /
        domain_length
    )

    hyphen_count = (
        core_domain.count("-")
    )

    labels = core_domain.split(
        "."
    )

    label_count = len(
        labels
    )

    longest_label_length = max(
        (
            len(label)
            for label in labels
        ),
        default=0
    )

    bigram_score = (
        bigram_model.score(domain)
    )

    trigram_score = (
        trigram_model.score(domain)
    )

    feature_row = [

        domain_length,
        digit_count,
        digit_ratio,
        vowel_ratio,
        consonant_ratio,
        entropy,
        unique_char_ratio,
        hyphen_count,
        label_count,
        longest_label_length,
        bigram_score,
        trigram_score

    ]

    return pd.DataFrame(
        [feature_row],
        columns=feature_names
    )


# ============================================================
# 6. REQUEST SCHEMA
# ============================================================

class DomainRequest(BaseModel):

    domain: str


# ============================================================
# 7. HEALTH
# ============================================================

@app.get("/health")
def health():

    return {

        "status": "healthy",

        "model_loaded":
            "model" in model_pipeline,

        "features_loaded":
            len(
                model_pipeline.get(
                    "features",
                    []
                )
            )

    }


# ============================================================
# 8. PREDICT
# ============================================================

@app.post("/predict")
def predict(
    payload: DomainRequest
):

    if "model" not in model_pipeline:

        raise HTTPException(
            status_code=500,
            detail="DGA model is not loaded."
        )

    domain = (
        payload.domain
        .lower()
        .strip()
    )

    if not domain:

        raise HTTPException(
            status_code=400,
            detail="Domain cannot be empty."
        )

    start = time.perf_counter()

    features = extract_features(

        domain,

        model_pipeline[
            "bigram_model"
        ],

        model_pipeline[
            "trigram_model"
        ],

        model_pipeline[
            "features"
        ]

    )

    model = model_pipeline[
        "model"
    ]

    prediction = int(
        model.predict(
            features
        )[0]
    )

    if hasattr(
        model,
        "predict_proba"
    ):

        probability = float(
            model.predict_proba(
                features
            )[0][1]
        )

    else:

        probability = float(
            prediction
        )

    latency = (
        time.perf_counter()
        - start
    ) * 1000

    return {

        "domain": payload.domain,

        "prediction":
            "DGA"
            if prediction == 1
            else "LEGIT",

        "probability":
            round(
                probability,
                4
            ),

        "is_dga":
            prediction == 1,

        "latency_ms":
            round(
                latency,
                2
            )

    }


# ============================================================
# 9. RUN SERVER
# ============================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000
    )
