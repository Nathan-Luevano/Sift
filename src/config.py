import os
import logging
from dotenv import load_dotenv

load_dotenv()

class Config:
    def __init__(self):
        self.DATABASE_PATH = os.getenv('DATABASE_PATH', './sift.db')
        self.LOG_LEVEL = getattr(logging, os.getenv('LOG_LEVEL', 'INFO').upper())
        self.LOG_FILE = os.getenv('LOG_FILE', './logs/sift.log')
        
        self.TWITTER_API_KEY = os.getenv('TWITTER_API_KEY', '')
        self.TWITTER_API_SECRET = os.getenv('TWITTER_API_SECRET', '')
        self.TWITTER_ACCESS_TOKEN = os.getenv('TWITTER_ACCESS_TOKEN', '')
        self.TWITTER_ACCESS_TOKEN_SECRET = os.getenv('TWITTER_ACCESS_TOKEN_SECRET', '')
        
        self.REDDIT_CLIENT_ID = os.getenv('REDDIT_CLIENT_ID', '')
        self.REDDIT_CLIENT_SECRET = os.getenv('REDDIT_CLIENT_SECRET', '')
        self.REDDIT_USER_AGENT = os.getenv('REDDIT_USER_AGENT', 'SiftApp/1.0')
        
        self.GOOGLE_MAPS_API_KEY = os.getenv('GOOGLE_MAPS_API_KEY', '')
        self.NEWS_API_KEY = os.getenv('NEWS_API_KEY', '')
        
        self.FLASK_SECRET_KEY = os.getenv('FLASK_SECRET_KEY', 'dev-key-change-in-production')
        self.FLASK_HOST = os.getenv('FLASK_HOST', '127.0.0.1')
        self.FLASK_PORT = int(os.getenv('FLASK_PORT', 5000))
        self.FLASK_DEBUG = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
        
        self.MAX_CORRELATION_DISTANCE_KM = float(os.getenv('MAX_CORRELATION_DISTANCE_KM', 50))
        self.CORRELATION_TIME_WINDOW_HOURS = int(os.getenv('CORRELATION_TIME_WINDOW_HOURS', 24))
        self.MAX_OSINT_RESULTS = int(os.getenv('MAX_OSINT_RESULTS', 1000))
        
        # local LLM settings
        self.OLLAMA_HOST = os.getenv('OLLAMA_HOST', 'http://localhost:11434')
        self.OLLAMA_MODEL = os.getenv('OLLAMA_MODEL', 'gemma:4b')
        self.OLLAMA_TIMEOUT = int(os.getenv('OLLAMA_TIMEOUT', 120))
        self.OLLAMA_ENABLE = os.getenv('OLLAMA_ENABLE', 'True').lower() == 'true'
        
        # web search settings
        self.WEB_SEARCH_ENABLE = os.getenv('WEB_SEARCH_ENABLE', 'True').lower() == 'true'
        self.WEB_SEARCH_ENGINE = os.getenv('WEB_SEARCH_ENGINE', 'google')
        self.WEB_SEARCH_MAX_RESULTS = int(os.getenv('WEB_SEARCH_MAX_RESULTS', 50))
        self.WEB_SEARCH_TIMEOUT = int(os.getenv('WEB_SEARCH_TIMEOUT', 45))
        self.WEB_SCRAPE_TIMEOUT = int(os.getenv('WEB_SCRAPE_TIMEOUT', 20))
        self.WEB_SCRAPE_MAX_PAGES = int(os.getenv('WEB_SCRAPE_MAX_PAGES', 15))
        
        # fancy search options
        self.GOOGLE_SEARCH_ENGINE_ID = os.getenv('GOOGLE_SEARCH_ENGINE_ID', '')
        self.GOOGLE_SEARCH_API_KEY = os.getenv('GOOGLE_SEARCH_API_KEY', '')
        self.SERPAPI_KEY = os.getenv('SERPAPI_KEY', '')
        
        self.SEARCH_DEPTH = os.getenv('SEARCH_DEPTH', 'deep')
        self.SEARCH_STRATEGY = os.getenv('SEARCH_STRATEGY', 'multi_engine')
        self.ENABLE_SOCIAL_SEARCH = os.getenv('ENABLE_SOCIAL_SEARCH', 'True').lower() == 'true'
        self.ENABLE_NEWS_ARCHIVE_SEARCH = os.getenv('ENABLE_NEWS_ARCHIVE_SEARCH', 'True').lower() == 'true'
        self.ENABLE_ACADEMIC_SEARCH = os.getenv('ENABLE_ACADEMIC_SEARCH', 'True').lower() == 'true'
        self.SEARCH_LANGUAGES = os.getenv('SEARCH_LANGUAGES', 'en').split(',')
        self.SEARCH_REGIONS = os.getenv('SEARCH_REGIONS', 'us').split(',')
        self.ENABLE_REVERSE_IMAGE_SEARCH = os.getenv('ENABLE_REVERSE_IMAGE_SEARCH', 'True').lower() == 'true'
        
        # selenium browser settings
        self.BROWSER_HEADLESS = os.getenv('BROWSER_HEADLESS', 'True').lower() == 'true'
        self.BROWSER_TIMEOUT = int(os.getenv('BROWSER_TIMEOUT', 30))
        self.BROWSER_USER_AGENT = os.getenv('BROWSER_USER_AGENT', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
        
        # how the LLM should behave
        self.LLM_MAX_TOKENS = int(os.getenv('LLM_MAX_TOKENS', 4096))
        self.LLM_TEMPERATURE = float(os.getenv('LLM_TEMPERATURE', 0.3))
        self.LLM_CONTEXT_WINDOW = int(os.getenv('LLM_CONTEXT_WINDOW', 8192))
        
        os.makedirs(os.path.dirname(self.LOG_FILE), exist_ok=True)
        
        logging.basicConfig(
            level=self.LOG_LEVEL,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.LOG_FILE),
                logging.StreamHandler()
            ]
        )

config = Config()