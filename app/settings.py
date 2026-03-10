from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    database_path: str = "data/guardian.db"
    temp_threshold: float = 0.60
    permanent_threshold: float = 0.70
    min_votes: int = 3
    ai_weight: float = 0.40
    vote_weight: float = 0.60
    ollama_base_url: str = "http://127.0.0.1:11434"
    ollama_model: str = ""
    ollama_timeout_seconds: int = 45
    fetch_timeout_seconds: int = 8
    max_fetch_bytes: int = 150000
    max_evidence_urls: int = 3
    max_context_chars_per_url: int = 2500
    max_total_context_chars: int = 5000
    ollama_temperature: float = 0.0
    ollama_num_predict: int = 256


settings = Settings()
