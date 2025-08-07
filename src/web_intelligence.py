import requests
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import time
import hashlib
from urllib.parse import urlparse, urljoin
import re

# web scraping stuff
from bs4 import BeautifulSoup
from newspaper import Article, Config as NewspaperConfig
from readability import Document
import markdownify

# search engine libraries
from duckduckgo_search import DDGS

# selenium for the tricky sites
from selenium import webdriver
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager
from webdriver_manager.firefox import GeckoDriverManager

from llm_client import OllamaClient

logger = logging.getLogger(__name__)

class WebIntelligenceCollector:
    def __init__(self, config):
        self.config = config
        self.llm_client = OllamaClient(config) if config.OLLAMA_ENABLE else None
        
        # configure newspaper3k for better article parsing
        self.newspaper_config = NewspaperConfig()
        self.newspaper_config.browser_user_agent = config.BROWSER_USER_AGENT
        self.newspaper_config.request_timeout = config.WEB_SCRAPE_TIMEOUT
        
        # persistent session for better performance
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': config.BROWSER_USER_AGENT,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Cache-Control': 'no-cache',
        })
        
        self.driver = None
        
    def collect_web_intelligence(self, forensic_context: Dict, location: str = "", start_time: datetime = None, end_time: datetime = None) -> List[Dict[str, Any]]:
        # this is the main intelligence gathering function
        
        if not self.config.WEB_SEARCH_ENABLE:
            logger.info("Web search is disabled")
            return []
        
        logger.info("Starting LLM-powered web intelligence collection")
        
        # let the LLM come up with smart search queries
        search_queries = self._generate_smart_search_queries(forensic_context, location, start_time, end_time)
        
        if not search_queries:
            logger.warning("No search queries generated")
            return []
        
        logger.info(f"Generated {len(search_queries)} intelligent search queries")
        
        all_results = []
        
        for query in search_queries:
            try:
                logger.info(f"Searching for: {query}")
                
                # try different search engines
                search_results = self._search_web(query)
                
                # grab the content from promising results
                analyzed_results = []
                for result in search_results[:self.config.WEB_SCRAPE_MAX_PAGES]:
                    try:
                        content_data = self._extract_and_analyze_content(result, forensic_context)
                        if content_data and content_data.get('relevance_score', 0) > 3:
                            analyzed_results.append(content_data)
                    except Exception as e:
                        logger.debug(f"Error processing result {result.get('url', 'unknown')}: {e}")
                        continue
                
                all_results.extend(analyzed_results)
                
                # don't hammer the search engines
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"Error processing query '{query}': {e}")
                continue
        
        # clean up duplicates and rank by relevance
        unique_results = self._deduplicate_results(all_results)
        ranked_results = sorted(unique_results, key=lambda x: x.get('relevance_score', 0), reverse=True)
        
        logger.info(f"Collected {len(ranked_results)} unique web intelligence items")
        
        return ranked_results[:self.config.MAX_OSINT_RESULTS]
    
    def _generate_smart_search_queries(self, forensic_context: Dict, location: str, start_time: datetime, end_time: datetime) -> List[str]:
        # have the LLM generate smart queries based on what we found
        
        if not self.llm_client or not self.llm_client.is_available():
            # use simple queries if LLM isn't working
            return self._generate_basic_queries(forensic_context, location)
        
        # prep the context for the LLM
        context_parts = []
        
        if forensic_context:
            if isinstance(forensic_context, dict):
                file_types = forensic_context.get('file_types', [])
                event_types = forensic_context.get('event_types', [])
                suspicious_files = forensic_context.get('suspicious_files', [])
                
                context_parts.append(f"File types involved: {', '.join(file_types)}")
                context_parts.append(f"Event types: {', '.join(event_types)}")
                if suspicious_files:
                    context_parts.append(f"Suspicious files: {', '.join(suspicious_files)}")
            else:
                context_parts.append(str(forensic_context))
        
        context_string = ". ".join(context_parts)
        timeframe = f"{start_time.strftime('%Y-%m-%d')} to {end_time.strftime('%Y-%m-%d')}" if start_time and end_time else ""
        
        try:
            queries = self.llm_client.generate_search_queries(context_string, location, timeframe)
            if queries:
                return queries
        except Exception as e:
            logger.error(f"Error generating LLM queries: {e}")
        
        # LLM didn't work, use basic queries
        return self._generate_basic_queries(forensic_context, location)
    
    def _generate_basic_queries(self, forensic_context: Dict, location: str) -> List[str]:
        # basic query generation when LLM isn't available
        queries = []
        
        base_terms = ["cybersecurity", "security incident", "data breach", "malware", "cyberattack"]
        
        if location:
            for term in base_terms:
                queries.append(f'"{term}" "{location}"')
        
        if isinstance(forensic_context, dict):
            file_types = forensic_context.get('file_types', [])
            for file_type in file_types:
                if file_type in ['exe', 'dll', 'bat', 'ps1']:
                    queries.append(f'malware {file_type} {location}')
        
        # throw in some general security queries too
        queries.extend([
            f"security breach {location}",
            f"cyber attack {location}",
            f"suspicious activity {location}",
            f"incident response {location}"
        ])
        
        return queries[:10]
    
    def _search_web(self, query: str) -> List[Dict[str, Any]]:
        # do the actual web search
        
        if self.config.WEB_SEARCH_ENGINE.lower() == 'duckduckgo':
            return self._search_duckduckgo(query)
        else:
            logger.warning(f"Unsupported search engine: {self.config.WEB_SEARCH_ENGINE}")
            return []
    
    def _search_duckduckgo(self, query: str) -> List[Dict[str, Any]]:
        # use DuckDuckGo for the search
        results = []
        
        try:
            with DDGS() as ddgs:
                ddg_results = list(ddgs.text(
                    keywords=query,
                    max_results=self.config.WEB_SEARCH_MAX_RESULTS,
                    timelimit='y',  # only last year's results
                    safesearch='off'
                ))
                
                for result in ddg_results:
                    results.append({
                        'title': result.get('title', ''),
                        'url': result.get('href', ''),
                        'snippet': result.get('body', ''),
                        'source': 'duckduckgo'
                    })
                    
        except Exception as e:
            logger.error(f"DuckDuckGo search error: {e}")
        
        return results
    
    def _extract_and_analyze_content(self, search_result: Dict, forensic_context: Dict) -> Optional[Dict[str, Any]]:
        # grab content from the page and have LLM analyze it
        
        url = search_result.get('url', '')
        if not url:
            return None
        
        try:
            # newspaper3k usually works well for articles
            content = self._extract_with_newspaper(url)
            
            if not content:
                # try basic scraping if newspaper fails
                content = self._extract_with_requests(url)
            
            if not content:
                # fire up selenium for the really tricky sites
                content = self._extract_with_browser(url)
            
            if not content or len(content) < 100:
                return None
            
            # have the LLM take a look at what we found
            analysis = None
            relevance_score = 5  # middle of the road default
            
            if self.llm_client and self.llm_client.is_available():
                try:
                    analysis = self.llm_client.analyze_web_content(
                        content=content,
                        context=str(forensic_context),
                        question="How does this content relate to digital forensic evidence?"
                    )
                    
                    if analysis:
                        relevance_score = analysis.get('correlation_potential', 5)
                        
                except Exception as e:
                    logger.debug(f"LLM analysis failed for {url}: {e}")
            
            # put together the final result
            result = {
                'timestamp': datetime.now(),
                'source': 'web_intelligence',
                'url': url,
                'title': search_result.get('title', ''),
                'content': content[:2000],  # keep it reasonable size
                'full_content': content,
                'snippet': search_result.get('snippet', ''),
                'relevance_score': relevance_score,
                'extraction_method': 'newspaper',
                'analysis': analysis,
                'author': 'Web Intelligence',
                'location': '',  # maybe fill this in later with geolocation
                'coordinates': None,
                'engagement': {},
                'data': {
                    'domain': urlparse(url).netloc,
                    'content_length': len(content),
                    'extraction_timestamp': datetime.now().isoformat()
                }
            }
            
            return result
            
        except Exception as e:
            logger.error(f"Error extracting content from {url}: {e}")
            return None
    
    def _extract_with_newspaper(self, url: str) -> Optional[str]:
        # try to get clean article text with newspaper3k
        try:
            article = Article(url, config=self.newspaper_config)
            article.download()
            article.parse()
            
            if article.text and len(article.text) > 100:
                content = f"{article.title}\n\n{article.text}"
                if article.summary:
                    content += f"\n\nSummary: {article.summary}"
                return content
                
        except Exception as e:
            logger.debug(f"Newspaper extraction failed for {url}: {e}")
        
        return None
    
    def _extract_with_requests(self, url: str) -> Optional[str]:
        # fallback to basic scraping
        try:
            response = self.session.get(
                url, 
                timeout=self.config.WEB_SCRAPE_TIMEOUT,
                allow_redirects=True
            )
            response.raise_for_status()
            
            # readability helps clean up the HTML mess
            doc = Document(response.text)
            clean_html = doc.summary()
            
            # markdown is easier to work with
            text_content = markdownify.markdownify(clean_html)
            
            # tidy up the extracted text
            text_content = re.sub(r'\n\s*\n', '\n\n', text_content)
            text_content = re.sub(r'[^\S\r\n]+', ' ', text_content)
            
            return text_content.strip()
            
        except Exception as e:
            logger.debug(f"Requests extraction failed for {url}: {e}")
        
        return None
    
    def _extract_with_browser(self, url: str) -> Optional[str]:
        # selenium time - for the JavaScript heavy sites
        if not self._setup_browser():
            return None
        
        try:
            self.driver.get(url)
            
            # give the page time to fully load
            WebDriverWait(self.driver, self.config.BROWSER_TIMEOUT).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            
            # look for the actual content sections
            content_selectors = [
                'article', 'main', '.content', '.post', '.entry',
                '.article-body', '.story-body', '#content'
            ]
            
            content = ""
            for selector in content_selectors:
                try:
                    elements = self.driver.find_elements(By.CSS_SELECTOR, selector)
                    if elements:
                        content = elements[0].text
                        break
                except:
                    continue
            
            # if nothing else works, grab everything
            if not content:
                content = self.driver.find_element(By.TAG_NAME, "body").text
            
            return content
            
        except Exception as e:
            logger.debug(f"Browser extraction failed for {url}: {e}")
            return None
        finally:
            if self.driver:
                try:
                    self.driver.quit()
                    self.driver = None
                except:
                    pass
    
    def _setup_browser(self) -> bool:
        # configure Chrome for scraping
        if self.driver:
            return True
        
        try:
            chrome_options = ChromeOptions()
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--disable-web-security')
            chrome_options.add_argument('--disable-features=VizDisplayCompositor')
            chrome_options.add_argument(f'--user-agent={self.config.BROWSER_USER_AGENT}')
            
            if self.config.BROWSER_HEADLESS:
                chrome_options.add_argument('--headless')
            
            # Chrome is usually more reliable
            try:
                self.driver = webdriver.Chrome(
                    service=webdriver.chrome.service.Service(ChromeDriverManager().install()),
                    options=chrome_options
                )
                return True
            except Exception as e:
                logger.debug(f"Chrome setup failed: {e}")
            
            # Firefox as backup option
            firefox_options = FirefoxOptions()
            if self.config.BROWSER_HEADLESS:
                firefox_options.add_argument('--headless')
            
            try:
                self.driver = webdriver.Firefox(
                    service=webdriver.firefox.service.Service(GeckoDriverManager().install()),
                    options=firefox_options
                )
                return True
            except Exception as e:
                logger.debug(f"Firefox setup failed: {e}")
                
        except Exception as e:
            logger.error(f"Browser setup failed: {e}")
        
        return False
    
    def _deduplicate_results(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        # get rid of duplicate results
        seen_urls = set()
        seen_hashes = set()
        unique_results = []
        
        for result in results:
            url = result.get('url', '')
            content = result.get('content', '')
            
            # already processed this URL
            if url in seen_urls:
                continue
            
            # hash the content to catch near-duplicates
            content_hash = hashlib.md5(content.encode('utf-8', errors='ignore')).hexdigest()
            if content_hash in seen_hashes:
                continue
            
            seen_urls.add(url)
            seen_hashes.add(content_hash)
            unique_results.append(result)
        
        return unique_results
    
    def analyze_web_trend(self, search_queries: List[str], location: str) -> Dict[str, Any]:
        # let the LLM analyze trends in what we found
        
        if not self.llm_client or not self.llm_client.is_available():
            return {"error": "LLM not available for trend analysis"}
        
        # grab some results from different searches
        sample_results = []
        for query in search_queries[:3]:  # just a few to avoid overdoing it
            results = self._search_web(query)
            sample_results.extend(results[:5])
        
        # mash all the results together for analysis
        combined_content = "\n".join([
            f"Title: {r.get('title', '')}\nSnippet: {r.get('snippet', '')}"
            for r in sample_results[:20]
        ])
        
        system_prompt = """Analyze web search results to identify trends and patterns relevant to cybersecurity 
        and digital forensics. Look for emerging threats, incident patterns, geographic trends, and temporal correlations.
        
        Return analysis as JSON with:
        - trending_topics: List of trending security topics
        - threat_indicators: Potential security threats identified
        - geographic_patterns: Location-based patterns
        - temporal_patterns: Time-based trends
        - recommendations: Actionable intelligence recommendations
        """
        
        prompt = f"""Analyze these web search results for cybersecurity trends and patterns:

Location Context: {location}
Search Results:
{combined_content[:3000]}

Provide trend analysis as JSON:"""
        
        try:
            response = self.llm_client.generate(prompt, system_prompt, max_tokens=2048)
            if response:
                import json
                json_match = re.search(r'\{.*\}', response, re.DOTALL)
                if json_match:
                    return json.loads(json_match.group())
        except Exception as e:
            logger.error(f"Error analyzing web trends: {e}")
        
        return {"error": "Failed to analyze web trends"}
    
    def __del__(self):
        # clean up selenium stuff
        if hasattr(self, 'driver') and self.driver:
            try:
                self.driver.quit()
            except:
                pass