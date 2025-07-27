from pathlib import Path

DATA_DIR = Path(__file__).parent / 'data'
DATA_FILE = DATA_DIR / 'network_data.json'
METRICS_FILE = DATA_DIR / 'model_metrics.json'
HISTORY_FILE = DATA_DIR / 'training_history.json'
TEST_LOGS_FILE = DATA_DIR / 'test_logs.json' 